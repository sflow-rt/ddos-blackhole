$(function() { 
  var dataURL = '../scripts/ddos.js/trend/json';
  var controlsURL = '../scripts/ddos.js/controls/json';
  var thresholdURL = '../scripts/ddos.js/threshold/json';
  var blockMinutesURL = '../scripts/ddos.js/blockminutes/json';
  var groupsURL = '../scripts/ddos.js/groups/json';
  var groupsInfoURL = '../scripts/ddos.js/groups/info/json';

  var defaults = {
    tab:0,
    charts0:'show',
    charts1:'hide',
    charts2:'hide',
    charts3:'hide',
    hlp0:'hide',
    hlp1:'hide',
    hlp2:'hide',
    hlp3:'hide',
    hlp4:'hide',
    hlp5:'hide'
  };

  var state = {};
  $.extend(state,defaults);

  function createQuery(params) {
    var query, key, value;
    for(key in params) {
      value = params[key];
      if(value == defaults[key]) continue;
      if(query) query += '&';
      else query = '';
      query += encodeURIComponent(key)+'='+encodeURIComponent(value);
    }
    return query;
  }

  function getState(key, defVal) {
    return window.sessionStorage.getItem('ddos_blackhole_'+key) || state[key] || defVal;
  }

  function setState(key, val, showQuery) {
    state[key] = val;
    window.sessionStorage.setItem('ddos_blackhole_'+key, val);
    if(showQuery) {
      var query = createQuery(state);
      window.history.replaceState({},'',query ? '?' + query : './');
    }
  }

  function setQueryParams(query) {
    var vars, params, i, pair;
    vars = query.split('&');
    params = {};
    for(i = 0; i < vars.length; i++) {
      pair = vars[i].split('=');
      if(pair.length == 2) setState(decodeURIComponent(pair[0]), decodeURIComponent(pair[1]),false);
    }
  }

  var search = window.location.search;
  if(search) setQueryParams(search.substring(1));

  $('#charts-acc > div').each(function(idx) {
    $(this).accordion({
      heightStyle:'content',
      collapsible: true,
      active: getState('charts'+idx, 'hide') == 'show' ? 0 : false,
      activate: function(event, ui) {
        var newIndex = $(this).accordion('option','active');
        setState('charts'+idx, newIndex === 0 ? 'show' : 'hide', true);
        $.event.trigger({type:'updateChart'});
      }
    });
  });

  $('#help-acc > div').each(function(idx) {
    $(this).accordion({
      heightStyle:'content',
      collapsible: true,
      active: getState('hlp'+idx, 'hide') === 'show' ? 0 : false,
      activate: function(event, ui) {
        var newIndex = $(this).accordion('option','active');
        setState('hlp'+idx, newIndex === 0 ? 'show' : 'hide', true);
      }
    });
  });

  $('#tabs').tabs({
    active: getState('tab', 0),
    activate: function(event, ui) {
      var newIndex = ui.newTab.index();
      setState('tab', newIndex, true);
      $.event.trigger({type:'updateChart'});
    },
    create: function(event,ui) {
      $.event.trigger({type:'updateChart'});
    }
  });

  var db = {};
  var showThreshold = true;
  $('#targets').chart({
    type: 'topn',
    stack: false,
    includeOther:false,
    metric: 'top-5-targets',
    legendHeadings: ['Target IP','Target Group'],
    hrule:[{name:'threshold',color:'red',scale:showThreshold}],
    units: 'Packets per Second'},
  db);
  $('#protocols').chart({
    type: 'topn',
    stack: false,
    includeOther:false,
    metric: 'top-5-protocols',
    legendHeadings: ['Target IP','Protocol Stack'],
    units: 'Packets per Second'},
  db);
  $('#attacks').chart({
    type: 'trend',
    stack: true,
    legend: ['Active','Failed','Pending'],
    metrics: ['controls_blocked','controls_failed','controls_pending'],
    units: 'Number of Controls'},
  db);
  $('#connections').chart({
    type: 'trend',
    stack: false,
    metrics: ['connections'],
    units: 'Connections'},
  db);

  var lastControlsUpdate = 0;
  var dialog;
  var selectedTarget;
  function removeControl() {
    $.ajax({
      url:controlsURL,
      type:'get',
      data:{action:'allow',address:selectedTarget}
    });
    dialog.dialog("close");
  }
  function installControl() {
    $.ajax({
      url:controlsURL,
      type:'get',
      data:{action:'block',address:selectedTarget}
    });
    dialog.dialog("close");
  }
  function formatTime(ms) {
    var m = new Date(ms);
    return  m.getUTCFullYear() +"/"+
     ("0" + (m.getUTCMonth()+1)).slice(-2) +"/"+
     ("0" + m.getUTCDate()).slice(-2) + " " +
     ("0" + m.getUTCHours()).slice(-2) + ":" +
     ("0" + m.getUTCMinutes()).slice(-2) + ":" +
     ("0" + m.getUTCSeconds()).slice(-2);
  }

  var ctl_mode;
  function refreshControls() {
    $.ajax({
      url: controlsURL,
      dataType: 'json',
      success: function(data) {
        lastControlsUpdate = data.update;
        ctl_mode = data.enabled ? "automatic" : "manual";
        if('automatic' === ctl_mode) $('#automatic').click();
        else $('#manual').click();
        var body = $('#controlstable tbody');
        var rows;
        if(data.controls.length) {
          rows = '';
          for(var i = 0; i < data.controls.length; i++) {
            var entry = data.controls[i];
            rows += '<tr class="' + (i % 2 === 0 ? "even" : "odd") + '">';
            rows += '<td>' + entry.target + '</td>';
            rows += '<td>' + entry.group + '</td>';
            rows += '<td>' + entry.protocol + '</td>';
            rows += '<td>' + formatTime(entry.time) + '</td>';
            rows += '<td>' + entry.status + '</td>';
            rows += '</tr>';
          }
          body.html(rows);
          body
            .find('tr')
            .hover(
              function() { $(this).addClass("dynhoveron"); },
              function() { $(this).removeClass("dynhoveron"); }
            )
            .click(function() {
              var td = $(this).children()[0];
              selectedTarget = $(td).html();
              $('#target').html(selectedTarget);
              td = $(this).children()[4];
              var status = $(td).html();
              if('pending' !== status) {
                $(".ui-dialog-buttonpane button:contains('Install')")
                  .attr("disabled", true)
                  .addClass("ui-state-disabled");
              } else {
                $(".ui-dialog-buttonpane button:contains('Install')")
                  .attr("disabled", false)
                  .removeClass("ui-state-disabled");
              }
              dialog.dialog('open');
              $(':button').blur();
            }); 
        }
        else {
          rows = '<tr><td colspan="5" class="alignc"><i>No active controls</td></tr>';
          body.html(rows);
        }
      }
    });
  }

  function warningDialog(message) {
    $('<div>' + message + '</div>').dialog({dialogClass:'alert', modal:true, buttons:{'Close': function() { $(this).dialog('close'); }}})
  }

  function getThreshold() {
     $.ajax({
      url:thresholdURL, 
      dataType:'json',
      success: function(data) {
        $('#threshold').spinner('value', data);
      }
    });
  }

  getThreshold();

  function setThreshold() {
    var threshold =  Math.round($('#threshold').spinner('value'));
    var settings = threshold;
    $.ajax({
      url:thresholdURL, 
      type: 'POST',
      contentType:'application/json',
      data: JSON.stringify(settings)
    });
  }

  $('#threshold').spinner({min:10000,max:10000000,step:10000});
  $('#thresholdget').button({icons:{primary:'ui-icon-arrowrefresh-1-e'},text:false}).click(getThreshold);
  $('#thresholdset').button({icons:{primary:'ui-icon-arrowstop-1-n'},text:false}).click(setThreshold);

  function getBlockMinutes() {
     $.ajax({
      url:blockMinutesURL,
      dataType:'json',
      success: function(data) {
        $('#blockminutes').spinner('value', data);
      }
    });
  }

  getBlockMinutes();

  function setBlockMinutes() {
    var blockminutes =  Math.round($('#blockminutes').spinner('value'));
    var settings = blockminutes;
    $.ajax({
      url:blockMinutesURL,
      type: 'POST',
      contentType:'application/json',
      data: JSON.stringify(settings)
    });
  }

  $('#blockminutes').spinner({min:10,max:1440,step:10});
  $('#blockminutesget').button({icons:{primary:'ui-icon-arrowrefresh-1-e'},text:false}).click(getBlockMinutes);
  $('#blockminutesset').button({icons:{primary:'ui-icon-arrowstop-1-n'},text:false}).click(setBlockMinutes);

  function refreshGroups() {
    $.ajax({
      url:groupsInfoURL,
      dataType: 'json',
      success: function(data) {
        $('#numgroups').val(data.groups).removeClass(data.groups ? 'error' : 'good').addClass(data.groups ? 'good' : 'error');
        $('#numcidrs').val(data.cidrs).removeClass(data.cidrs ? 'error' : 'good').addClass(data.cidrs ? 'good' : 'error');
      }
    });
  }

  refreshGroups();

  function getGroups() {
    location.href = groupsURL;
  }

  $('#groupsrefresh').button({icons:{primary:'ui-icon-arrowrefresh-1-e'},text:false}).click(refreshGroups);
  $('#groupsget').button({icons:{primary:'ui-icon-search'},text:false}).click(getGroups);
  $('#groupsfile').hide().change(function(event) {
    var input = event.target;
    var reader = new FileReader();
    var $this = $(this);
    reader.onload = function(){
      var text = reader.result;
      $this.wrap('<form>').closest('form').get(0).reset();
      $this.unwrap();
      $.ajax({
        url:groupsURL,
        type: 'POST',
        contentType:'application/json',
        data:text,
        success:refreshGroups,
        error: function() { warningDialog('Badly formatted groups'); }
      });
    };
    reader.readAsText(input.files[0]);
  });
  $('#groupsset').button({icons:{primary:'ui-icon-arrowstop-1-n'},text:false}).click(function() {$('#groupsfile').click();}); 

  function updateData(data) {
    if(!data 
      || !data.trend 
      || !data.trend.times 
      || data.trend.times.length == 0) return;

    if(db.trend) {
      // merge in new data
      var maxPoints = db.trend.maxPoints;
      var remove = db.trend.times.length > maxPoints ? db.trend.times.length - maxPoints : 0;
      db.trend.times = db.trend.times.concat(data.trend.times);
      if(remove) db.trend.times = db.trend.times.slice(remove);
      for(var name in db.trend.trends) {
        db.trend.trends[name] = db.trend.trends[name].concat(data.trend.trends[name]);
        if(remove) db.trend.trends[name] = db.trend.trends[name].slice(remove);
      }
    } else db.trend = data.trend;

    db.trend.start = new Date(db.trend.times[0]);
    db.trend.end = new Date(db.trend.times[db.trend.times.length - 1]);
    db.trend.values = data.trend.values;

    $.event.trigger({type:'updateChart'});
  }

  function pollTrends() {
    $.ajax({
      url: dataURL,
      data: db.trend && db.trend.end ? {after:db.trend.end.getTime()} : null,
      success: function(data) {
        updateData(data);
        if(data && data.trend && data.trend.values && lastControlsUpdate !== data.trend.values.update) refreshControls();
        setTimeout(pollTrends, 1000);
      },
      error: function(result,status,errorThrown) {
        setTimeout(pollTrends,5000);
      },
      timeout: 60000
    });
  };

  $(window).resize(function() {
    $.event.trigger({type:'updateChart'});
  });

  dialog = $('#dialog').dialog({
    modal:true,
    autoOpen:false,
    buttons: {
      Remove:removeControl,
      Install:installControl,
      Close: function() { dialog.dialog("close"); } 
    }
  });
  $('#controller_mode').buttonset();
  $('#controller_mode').change(function(evt) {
    var newMode = $(evt.target).attr('id');
    if(newMode === ctl_mode) return;

    $.ajax({
      url:controlsURL,
      type:'get',
      data:{action:'automatic' === newMode ? 'enable' : 'disable'}
    }); 
    ctl_mode = newMode;
  });
  pollTrends();
  refreshControls();
  refreshGroups();
});
