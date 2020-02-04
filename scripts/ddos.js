// author: InMon
// version: 2.0
// date: 1/24/2020
// description: Blackhole DDoS flood attacks
// copyright: Copyright (c) 2015-2020 InMon Corp.

include(scriptdir()+'/inc/trend.js');

var router_ip = getSystemProperty("ddos_blackhole.router")   || '127.0.0.1';
var my_as     = getSystemProperty("ddos_blackhole.as")       || '65000';
var my_id     = getSystemProperty("ddos_blackhole.id")       || '0.6.6.6';
var community = getSystemProperty("ddos_blackhole.community")|| '65535:666';
var nexthop   = getSystemProperty("ddos_blackhole.nexthop")  || '192.0.2.1';
var localpref = getSystemProperty("ddos_blackhole.localpref")|| '100';

var effectiveSamplingRateFlag = getSystemProperty("ddos_blackhole.esr") === "yes";
var flow_t = getSystemProperty("ddos_blackhole.flow_seconds")|| '2';
var threshold_t = getSystemProperty("ddos_blackhole.threshold_seconds") || '60';

var externalGroup= getSystemProperty("ddos_blackhole.externalgroup")   || 'external';
var excludedGroups= getSystemProperty("ddos_blackhole.excludedgroups") || 'external,private,multicast,exclude';

var syslogHost = getSystemProperty("ddos_blackhole.syslog.host");
var syslogPort = getSystemProperty("ddos_blackhole.syslog.port") || '514';
var syslogFacility = getSystemProperty("ddos_blackhole.syslog.facility") || '16'; // local0
var syslogSeverity = getSystemProperty("ddos_blackhole.syslog.severity") || '5';  // notice

function sendEvent(action,ip,group,stack) {
  if(!syslogHost) return;

  var msg = {app:'ddos-blackhole',action:action,ip:ip,group:group};
  if(stack) msg.stack = stack;
  try {
    syslog(syslogHost,syslogPort,syslogFacility,syslogSeverity,msg);
  } catch(e) {
    logWarning("DDoS cannot send syslog to " + syslogHost); 
  }
}

var defaultGroups = {
  external:['0.0.0.0/0'],
  private:['10.0.0.0/8','172.16.0.0/12','192.168.0.0/16','169.254.0.0/16'],
  multicast:['224.0.0.0/4']
};

getSystemPropertyNames()
  .filter(p => p.match('^ddos_blackhole\\.group\\.'))
  .forEach(function(prop) {
    var [,,name] = prop.split('.');
    defaultGroups[name] = getSystemProperty(prop).split(',');
});

var filter = 'group:ipsource:ddos_blackhole='+externalGroup;
filter += '&group:ipdestination:ddos_blackhole!='+excludedGroups;

var groups = storeGet('groups') || defaultGroups;
var threshold = storeGet('threshold') || getSystemProperty("ddos_blackhole.threshold") || 1000000;
var block_minutes = storeGet('block_minutes') || getSystemProperty("ddos_blackhole.blockminutes") || 60;

var controls = {};

var update = 0;
var counts = {};
function updateControlCounts() {
  update++;
  counts = { n: 0, blocked: 0, pending: 0, failed: 0 };
  for(var addr in controls) {
    counts.n++;
    switch(controls[addr].status) {
    case 'blocked':
      counts.blocked++;
      break;
    case 'pending':
      counts.pending++;
      break;
    case 'failed':
      counts.failed++;
      break;
    } 
  }
}

var enabled = storeGet('enabled') || ("automatic" === getSystemProperty("ddos_blackhole.actions")) || false;

var bgpUp = false;

function blockRoute(address) {
  return {prefix:address, nexthop:nexthop, communities:community, localpref:localpref};
}

function bgpOpen() {
  bgpUp = true;

  // re-install controls
  for(var addr in controls) {
    var rec = controls[addr];
    if(rec.status === 'blocked' || rec.status === 'failed') {
      if(bgpAddRoute(router_ip, blockRoute(addr))) {
        rec.status = 'blocked';
      }
      else {
        logWarning("DDoS block failed, " + addr);
        rec.status = 'failed';
      } 
    }
  }
  updateControlCounts();
}

function bgpClose() {
  bgpUp = false;

  // update control status
  for(var addr in controls) {
    var rec = controls[addr];
    if(rec.status === 'blocked') rec.status = 'failed';
  }
  updateControlCounts();
}

bgpAddNeighbor(router_ip, my_as, my_id, null, bgpOpen, bgpClose);

setGroups('ddos_blackhole', groups);

setFlow('ddos_blackhole_target', 
  { keys:'ipdestination,group:ipdestination:ddos_blackhole', value:'frames', filter:filter, t:flow_t }
);
setFlow('ddos_blackhole_protocol',
  { keys:'ipdestination,stack', value:'frames', filter:filter, t:flow_t }
);

function setDDoSThreshold(pps) {
  setThreshold('ddos_blackhole_attack',
    {metric:'ddos_blackhole_target',value:threshold,byFlow:true,timeout:threshold_t}
  );
}

setDDoSThreshold(threshold);

function block(address,info,operator) {
  if(!controls[address]) {
    logInfo("DDoS blocking " + address + " " + info.group + (info.stack ? " " + info.stack : ""));
    sendEvent('block',address,info.group,info.stack);
    let rec = { action: 'block', time: (new Date()).getTime(), status:'pending', info:info };
    controls[address] = rec;
    if(enabled || operator) {
      if(bgpAddRoute(router_ip, blockRoute(address))) {
        rec.status = 'blocked';
      }
      else {
        logWarning("DDoS block failed, " + address);
        rec.status = 'failed';
      }
    }
  } else if(operator) {
    // operator confirmation of existing control
    let rec = controls[address];
    if('pending' === rec.status) {
      if(bgpAddRoute(router_ip,blockRoute(address))) {
        rec.status = 'blocked';
      }
      else {
        logWarning("DDoS block failed, " + address);
        rec.status = 'failed';
      }
    }
  }
  updateControlCounts();
}

function allow(address,operator) {
  if(controls[address]) {
    let rec = controls[address];
    if(!operator) {
      let evt = rec.info.event;
      if(thresholdTriggered(evt.thresholdID,evt.agent,evt.dataSource+'.'+evt.metric,evt.flowKey)) {
        return;
      }
    }
    logInfo("DDoS allowing " + address + " " + rec.info.group + (rec.info.stack ? " " + rec.info.stack : ""));
    sendEvent('allow',address,rec.info.group,rec.info.stack);
    if('blocked' === rec.status) {
      if(bgpRemoveRoute(router_ip,address)) {
        delete controls[address];
      }
      else {
        logWarning("DDoS allow failed, " + address);
        rec.status = 'failed';
      }
    } else {
      delete controls[address];
    }
  }
  updateControlCounts();
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
      logWarning("DDoS effectiveSampling rate " + rate + " too high for " + evt.agent);
      return;
    }
  }

  // gather supporting data
  var info = {group:group,event:evt};
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

var trend = new Trend(300,1);

var other = '-other-';
function calculateTopN(metric,n,minVal,total_pps) {
  var total, top, topN, i, pps;
  top = activeFlows('ALL',metric,n,minVal,'max');
  var topN = {};
  if(top) {
    total = 0;
    for(i in top) {
      pps = top[i].value;
      topN[top[i].key] = pps;
      total += pps;
    }
    if(total_pps > total) topN[other] = total_pps - total;
  }
  return topN;
}

setIntervalHandler(function(now) {
  var points = {};
  points['controls'] = counts.n || 0;
  points['controls_pending'] = counts.pending || 0;
  points['controls_failed'] = counts.failed || 0;
  points['controls_blocked'] = counts.blocked || 0;
  points['connections'] = bgpUp ? 1 : 0;
  points['top-5-targets'] = calculateTopN('ddos_blackhole_target',5,1,0);
  points['top-5-protocols'] = calculateTopN('ddos_blackhole_protocol',5,1,0);
  trend.addPoints(now,points);

  var block_ms = 60000 * block_minutes;
  for(var addr in controls) {
    if(now - controls[addr].time > block_ms) allow(addr,false);
  }
}, 1);

setHttpHandler(function(req) {
  var result, key, name, path = req.path;
  if(!path || path.length == 0) throw "not_found";
  switch(path[0]) {
    case 'trend':
      if(path.length > 1) throw "not_found";
      result = {};
      result.trend = req.query.after ? trend.after(parseInt(req.query.after)) : trend;
      result.trend.values = {};
      if(threshold) result.trend.values.threshold = threshold;
      result.trend.values.update = update;
      break;
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
          if(address) allow(address,true);
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
      result.enabled = enabled;
      result.update = update;
      break;
    case 'threshold':
      if(path.length > 1) throw "not_found";
      switch(req.method) {
        case 'POST':
        case 'PUT':
          if(req.error) throw "bad_request";
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
          if(req.error) throw "bad_request";
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
