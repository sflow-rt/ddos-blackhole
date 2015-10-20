// author: InMon
// version: 1.0
// date: 10/10/2015
// description: Blackhole DDoS flood attacks
// copyright: Copyright (c) 2015 InMon Corp.

include(scriptdir()+'/inc/trend.js');

var router_ip = getSystemProperty("ddos_blackhole.router")   || '127.0.0.1';
var user      = getSystemProperty("ddos_blackhole.user")     || 'user';
var password  = getSystemProperty("ddos_blackhole.password") || 'password';

var externalGroup= getSystemProperty("ddos_blackhole.externalgroup")   || 'external';
var excludedGroups= getSystemProperty("ddos_blackhole.excludedgroups") || 'external,private,multicast';

var defaultGroups = {
  external:['0.0.0.0/0'],
  private:['10.0.0.0/8','172.16.0.0/12','192.168.0.0/16'],
  multicast:['224.0.0.0/4'],
};

var filter = 'group:ipsource:ddos_blackhole='+externalGroup;
filter += '&group:ipdestination:ddos_blackhole!='+excludedGroups;

var groups = storeGet('groups')               || defaultGroups;
var threshold = storeGet('threshold')         || 1000000;
var block_minutes = storeGet('block_minutes') || 60;

var controls;
var controls_n;
var controls_id = 0;

var enabled = storeGet('enabled') || false;

var effectiveSamplingRateFlag = false;

// modify nullRoute function to select alternative control script
// or implement controls using http()/syslog() clients
// op   = set|clear
// addr = IP v4 address
function nullRoute(op, addr) {
  var result = runCmd(
    ['expect','-f','commands.exp',router_ip,user,password,'null_route',op, addr],
    null,
    scriptdir()+'/controls'
  );
  if(result.status !== 0) throw "runCmd failed, status=" + result.status;
}

function updateControlCount() {
  controls_n= 0;
  for(var addr in controls) controls_n++;
  sharedSet('ddos_blackhole_controls_n',controls_n);
  sharedSet('ddos_blackhole_controls_id',++controls_id);
}

function restoreControls() {
  try { controls = storeGet("controls") || {}; }
  catch(e) { logWarning("restoreControls, error=" + e.message); }
  updateControlCount();
}

function saveControls() {
  try { storeSet("controls", controls); }
  catch(e) { logWarning("saveControls, error=" + e.message); }
  updateControlCount();
}

// restore previous controls on startup
restoreControls();

setGroups('ddos_blackhole', groups);

var flow_t = 2;
setFlow('ddos_blackhole_target', 
  { keys:'ipdestination,group:ipdestination:ddos_blackhole', value:'frames', filter:filter, t:flow_t }
);
setFlow('ddos_blackhole_protocol',
  { keys:'ipdestination,stack', value:'frames', filter:filter, t:flow_t }
);

function setDDoSThreshold(pps) {
  setThreshold('ddos_blackhole_attack',
    {metric:'ddos_blackhole_target',value:threshold,byFlow:true,timeout:10}
  );
  sharedSet('ddos_blackhole_pps',pps);
}

setDDoSThreshold(threshold);

function block(address,info,operator) {
  if(!controls[address]) {
    logInfo("blocking " + address);
    let rec = { action: 'block', time: (new Date()).getTime(), status:'pending', info:info };
    controls[address] = rec;
    if(enabled || operator) {
      try {
        nullRoute('set', address);
        rec.status = 'blocked';
      }
      catch(e) {
        logWarning("block failed, " + address + " (" + e + ")");
        rec.status = 'failed';
      }
    }
    saveControls();
  } else if(operator) {
    // operator confirmation of existing control
    let rec = controls[address];
    if('pending' === rec.status) {
       try {
        nullRoute('set', address);
        rec.status = 'blocked';
      }
      catch(e) {
        logWarning("block failed, " + address + " (" + e + ")");
        rec.status = 'failed';
      }
      saveControls();
    }
  }
}

function allow(address,info,operator) {
  if(controls[address]) {
    logInfo("allowing " + address);
    let rec = controls[address];
    if('blocked' === rec.status) {
      delete controls[address];
      try {
        nullRoute('clear',address);
        delete controls[address];
      }
      catch(e) {
        logWarning("allow failed, " + address + " (" + e + ")");
        rec.status = 'failed';
      }
    } else delete controls[address];
    saveControls();
  }
}

setEventHandler(function(evt) {
  var [ip,group] = evt.flowKey.split(',');
  if(controls[ip]) return;

  // don't allow data from data sources with sampling rates close to threshold
  // avoids false positives due the insufficient samples
  if(effectiveSamplingRateFlag) {
    let dsInfo = datasourceInfo(evt.agent,evt.dataSource);
    if(!dsInfo) return;
    let rate = dsInfo.effectiveSamplingRate;
    if(!rate || rate > (threshold / 10)) {
      logWarning("effectiveSampling rate " + rate + " too high for " + evt.agent);
      return;
    }
  }

  // gather supporting data
  var info = {group:group};
  var keys = metric(evt.agent,evt.dataSource+'.ddos_blackhole_protocol')[0].topKeys;
  if(keys) {
    let majorityThresh = evt.value / 2;
    let entry = keys.find(function(el) el.key.split(',')[0] === ip && el.value > majorityThresh);
    if(entry) {
       let [,stack] = entry.key.split(',');
       info['stack'] = stack;
    }
  }

  block(ip,info,false);
},['ddos_blackhole_attack']);

setIntervalHandler(function() {
  var now = (new Date()).getTime();
  var threshMs = block_minutes * 60000;
  for(var addr in controls) {
    if(now - controls[addr].time > threshMs) allow(addr,{},false);
  }
}, 60);

setHttpHandler(function(req) {
  var result, key, name, path = req.path;
  if(!path || path.length == 0) throw "not_found";
  switch(path[0]) {
    case 'controls':
      result = {};
      var action = '' + req.query.action;
      switch(action) {
        case 'block':
          var address = req.query.address[0];
          if(address) block(address,{},true);
          break;
        case 'allow':
          var address = req.query.address[0];
          if(address) allow(address,{},true);
          break;
        case 'enable':
          enabled = true;
          storeSet('enabled',enabled)
          break;
        case 'disable':
          enabled = false;
          storeSet('enabled')
          break;
      }
      result.controls = [];
      for(addr in controls) {
        let ctl = controls[addr];
        let entry = {
          target: addr,
          group: ctl.info.group,
          protocol: ctl.info.stack ? ctl.info.stack : '',
          time: ctl.time,
          status: ctl.status 
        }
        result.controls.push(entry); 
      };
      result.id = controls_id;
      result.enabled = enabled;
      break;
    case 'threshold':
      if(path.length > 1) throw "not_found";
      switch(req.method) {
        case 'POST':
        case 'PUT':
          if(req.error) throw "bad_request"
          threshold = parseInt(req.body);
          setDDoSThreshold(threshold);
          storeSet('threshold',threshold);
          break;
        default:
          result = threshold;
      }
      break;
    case 'blockminutes':
      if(path.length > 1) throw "not_found";
      switch(req.method) {
        case 'POST':
        case 'PUT':
          if(req.error) throw "bad_request"
          block_minutes = parseInt(req.body);
          storeSet('block_minutes',block_minutes);
          break;
        default:
          result = block_minutes;
      }
      break;
    case 'groups':
      if(path.length > 1) {
        if(path.length === 2 && 'info' === path[1]) {
          let ngroups = 0; ncidrs = 0;
          for (let grp in groups) {
            ngroups++;
            ncidrs += groups[grp].length;
          }
          result = {groups:ngroups, cidrs:ncidrs}; 
        }
        else throw "not_found";
      } else {
        switch(req.method) {
          case 'POST':
          case 'PUT':
            if(req.error) throw "bad_request";
            if(!setGroups('ddos_blackhole', req.body)) throw "bad_request";
            groups = req.body;
            storeSet('groups', groups);
            break;
          default: return groups;
        }
      }
      break;
    default: throw 'not_found';
  }
  return result;
});
