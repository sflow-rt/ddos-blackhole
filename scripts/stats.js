// author: InMon
// version: 1.0
// date: 10/10/2015
// description: Blackhole DDoS flood attacks

include(scriptdir()+'/inc/trend.js');

var trend = new Trend(300,1);
var points;

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

setIntervalHandler(function() {
  points = {};
  points['controls'] = sharedGet('ddos_blackhole_controls_n') || 0;
  points['top-5-targets'] = calculateTopN('ddos_blackhole_target',5,1,0);
  points['top-5-protocols'] = calculateTopN('ddos_blackhole_protocol',5,1,0);
  trend.addPoints(points);  
}, 1);

setHttpHandler(function(req) {
  var result, key, name, threshold, id, path = req.path;
  if(!path || path.length == 0) throw "not_found";
  switch(path[0]) {
    case 'trend':
      if(path.length > 1) throw "not_found"; 
      result = {};
      result.trend = req.query.after ? trend.after(parseInt(req.query.after)) : trend;
      result.trend.values = {};
      threshold = sharedGet('ddos_blackhole_pps');
      if(threshold) result.trend.values.threshold = threshold;
      id = sharedGet('ddos_blackhole_controls_id') || 0;
      result.trend.values.control_id = id;
      break;
    default: throw 'not_found';
  }
  return result;
});
