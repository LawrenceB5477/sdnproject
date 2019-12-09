from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str
from pox.lib.util import str_to_bool
import time
#My imports
import datetime
from host_tracker.host_tracker import host_tracker
from openflow.discovery import Discovery as discovery 
import threading 
from bottle import Bottle 
import json 
from pox.openflow.of_json import *

log = core.getLogger()


# We don't want to flood immediately when a switch connects.
# Can be overriden on commandline.
_flood_delay = 0

class LearningSwitch (object):
  """
  For each packet from the switch:
  1) Use source address and switch port to update address/port table
  2) Is transparent = False and either Ethertype is LLDP or the packet's
     destination address is a Bridge Filtered address?
     Yes:
        2a) Drop packet -- don't forward link-local traffic (LLDP, 802.1x)
            DONE
  3) Is destination multicast?
     Yes:
        3a) Flood the packet
            DONE
  4) Port for destination address in our address/port table?
     No:
        4a) Flood the packet
            DONE
  5) Is output port the same as input port?
     Yes:
        5a) Drop packet and similar ones for a while
  6) Install flow table entry in the switch so that this
     flow goes out the appopriate port
     6a) Send the packet out appropriate port
  """
  def __init__ (self, connection, transparent, firewall, timeArray):
    # Switch we'll be adding L2 learning switch capabilities to
    self.connection = connection
    self.transparent = transparent

    # Our table
    self.macToPort = {}

    # Our firewall
    self.firewall = firewall

    # Our time restrictions
    self.timeArray = timeArray

    # We want to hear PacketIn messages, so we listen
    # to the connection
    connection.addListeners(self)

    # We just use this to know when to log a helpful message
    self.hold_down_expired = _flood_delay == 0

    #log.debug("Initializing LearningSwitch, transparent=%s",
    #          str(self.transparent))

  def _handle_PacketIn (self, event):
    """
    Handle packet in messages from the switch to implement above algorithm.
    """
    packet = event.parsed

    
    #This is where the firewall rules are kept and checked.
    def theRules(src, dst):

      #Concatenate the source and destination MAC address strings
      pair = src + dst

      #If the string is in the firewall dictionary.. return the value
      try:
        if pair in self.firewall:
          return self.firewall[pair]
      except KeyError:
        return False

    #Limit pings based on date and time
    def timeLimit(src, dst):

        now = datetime.datetime.now() 
        for a in self.timeArray:
            y = a.split()
            log.debug("in time!")
            startTime = datetime.datetime(int(y[2]),int(y[3]),int(y[4]),int(y[5]),int(y[6]))
            log.debug(event) 
            endTime = datetime.datetime(int(y[7]),int(y[8]),int(y[9]),int(y[10]),int(y[11]))
            #Source cannot ping destination within date and time range
            if y[0] == src and y[1] == dst:
                if now >= startTime and now < endTime:
                    return "no"
            #Nothing can ping source destination within date and time range
            elif y[0] == "*" and y[1] == dst:
                #Drop the packet if within date and time range
                if now >= startTime and now < endTime:
                    return "no"
            #Source cannot ping anything within date and time range
            elif y[0] == src and y[1] == "*":
                #Drop the packet if within date and time range
                if now >= startTime and now < endTime:
                    return "no"

    def flood (message = None):
      """ Floods the packet """
      msg = of.ofp_packet_out()
      if time.time() - self.connection.connect_time >= _flood_delay:
        # Only flood if we've been connected for a little while...

        if self.hold_down_expired is False:
          # Oh yes it is!
          self.hold_down_expired = True
          log.info("%s: Flood hold-down expired -- flooding",
              dpid_to_str(event.dpid))

        if message is not None: log.debug(message)
        #log.debug("%i: flood %s -> %s", event.dpid,packet.src,packet.dst)
        # OFPP_FLOOD is optional; on some switches you may need to change
        # this to OFPP_ALL.
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
      else:
        pass
        #log.info("Holding down flood for %s", dpid_to_str(event.dpid))
      msg.data = event.ofp
      msg.in_port = event.port
      self.connection.send(msg)

    def drop (duration = None):
      """
      Drops this packet and optionally installs a flow to continue
      dropping similar ones for a while
      """
      if duration is not None:
        if not isinstance(duration, tuple):
          duration = (duration,duration)
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet)
        msg.idle_timeout = duration[0]
        msg.hard_timeout = duration[1]
        msg.buffer_id = event.ofp.buffer_id
        self.connection.send(msg)
      elif event.ofp.buffer_id is not None:
        msg = of.ofp_packet_out()
        msg.buffer_id = event.ofp.buffer_id
        msg.in_port = event.port
        self.connection.send(msg)

    self.macToPort[packet.src] = event.port # 1
    
    #Turn the source and destination MAC addresses into strings
    src = str(packet.src)
    dst = str(packet.dst)

    #Drop the packet if the rule in the dictionary is False
    #Drop if the packet sends during a restricted time
   # if theRules(src,dst) == 'false':
    #  log.debug("Firewall blocked flow.") 
     # drop()
     # return 
    #if timeLimit(src, dst) == "no": 
    #  log.debug("Timerange blocked flow")
     # drop()
      #return

    if not self.transparent: # 2
      if packet.type == packet.LLDP_TYPE or packet.dst.isBridgeFiltered():
        drop() # 2a
        return

    if packet.dst.is_multicast:
      flood() # 3a
    else:
      if packet.dst not in self.macToPort: # 4
        flood("Port for %s unknown -- flooding" % (packet.dst,)) # 4a
      else:
        port = self.macToPort[packet.dst]
        if port == event.port: # 5
          # 5a
          log.warning("Same port for packet from %s -> %s on %s.%s.  Drop."
              % (packet.src, packet.dst, dpid_to_str(event.dpid), port))
          drop(10)
          return
        # 6
        log.debug("installing flow for %s.%i -> %s.%i" %
                  (packet.src, event.port, packet.dst, port))
        msg = of.ofp_flow_mod()
        match = of.ofp_match.from_packet(packet, event.port)
        msg.priority = 0 
        msg.match.dl_src = of.EthAddr(src)
        msg.match.dl_dst = of.EthAddr(dst) 
        msg.idle_timeout = 10
        msg.hard_timeout = 30
        msg.actions.append(of.ofp_action_output(port = port))
        msg.data = event.ofp # 6a
        self.connection.send(msg)


#this class is an event handler for core.openflow 
class l2_learning (object):
  """
  Waits for OpenFlow switches to connect and makes them learning switches.
  """
  
  def check_time(self):  
        now = datetime.datetime.now()
        for a in self.timeArray:
            y = a.split()
            src = y[0]
            dst = y[1]
            startTime = datetime.datetime(int(y[2]),int(y[3]),int(y[4]),int(y[5]),int(y[6]))
            endTime = datetime.datetime(int(y[7]),int(y[8]),int(y[9]),int(y[10]),int(y[11]))
            if y[0] == src and y[1] == dst:
                if now >= startTime and now < endTime:
                    log.debug(endTime)
                    log.debug(now)
                    if (src, dst, "date") not in self.rules:
                        self.rules.append((src,dst, "date"))
                else:
                    if (src, dst, "date") in self.rules:
                        self.rules.remove((src, dst, "date"))

            #Nothing can ping source destination within date and time range
            elif y[0] == "*" and y[1] == dst:
                #Drop the packet if within date and time range
                if now >= startTime and now < endTime:
                    if (src, dst, "date") not in self.rules:
                        self.rules.append((src,dst, "date"))
                else:
                    if (src, dst, "date") in self.rules:
                        self.rules.remove((src, dst, "date"))
            #Source cannot ping anything within date and time range
            elif y[0] == src and y[1] == "*":
                #Drop the packet if within date and time range
                if now >= startTime and now < endTime:
                    if (src, dst, "date") not in self.rules:
                        self.rules.append((src,dst, "date"))
                else:
                    if (src, dst, "date") in self.rules:
                        self.rules.remove((src, dst, "date"))

  def __init__ (self, transparent):
    core.listen_to_dependencies(self)
    self.transparent = transparent
    self.switches = set()
    self.links = set()
    self.hosts = {} 
    self.firewall = {} 
    self.timeArray = []
    self.usage = {} 
    self.usagecaps = {}
    self.rules = [] 
    
    from pox.lib.recoco import Timer
    Timer(10,self.get_flow_stats, recurring=True) 
    #Open file located in /home/mininet/pox
    f = open("firewall.txt", "r")

    #Split each line in the file into a list
    f1 = f.readlines()
    log.debug(f1)       
      #Each line gets split into an array. First two indexes are added
      #to the dictionary and the third index is the assigned value
    for x in f1:
         y = x.split()
         if len(y) != 3:
             continue
         desc = y[0] + y[1]
         self.firewall[desc] = y[2]
         if y[2] == "false":
            
            self.rules.append((y[0], y[1], "firewall"))


    #Open file located in /home/mininet/pox
    f = open("date_time.txt", "r")

    #Split each line in the file into a list
    f1 = f.readlines()

    #Add list items to the array
    for x in f1:
        self.timeArray.append(str(x))

    self.check_time()

    f = open("usage_caps.txt", "r")
    lines = f.readlines()
    for line in lines: 
        src, dst, limit = line.split(" ") 
        self.usagecaps[src + ":" + dst] = limit 

  def get_flow_stats(self):
    for con in core.openflow.connections:
        con.send(of.ofp_stats_request(body=of.ofp_flow_stats_request()))

  def propogate_rules(self, connection):
    log.debug("Propogating rules!")
    self.check_time()
    for rule in self.rules:
        src, dest, type = rule
        msg = of.ofp_flow_mod()
        msg.match.dl_src = of.EthAddr(src)
        msg.match.dl_dst = of.EthAddr(dest)
        msg.idle_timeout = 10
        msg.hard_timeout = 30
        msg.actions.append(of.ofp_action_output(port = of.OFPP_NONE)) 
        connection.send(msg)

	# called when a new switch connects. 
  def _handle_openflow_ConnectionUp (self, event):
    log.debug("Connection up %s" % (event.connection,))
    switch = dpid_to_str(event.dpid) 
    if switch not in self.switches:
        self.switches.add(switch) 
    LearningSwitch(event.connection, self.transparent, self.firewall, self.timeArray) 
    self.propogate_rules(event.connection)
    from pox.lib.recoco import Timer

    Timer(10, lambda :self. propogate_rules(event.connection), recurring=True) 

    # called when a switch disconnects 
  def _handle_openflow_ConnectionDown(self, event):
    log.debug("Connection down %s" % (event.connection))
    switch = dpid_to_str(event.dpid) 
    if switch in self.switches:
        self.switches.remove(switch) 

    # when the host tracker gets registered with the core registry 
  def _handle_core_ComponentRegistered(self, event): 
    if event.name == "host_tracker":
        log.debug("Host tracker loaded!") 
        event.component.addListenerByName("HostEvent", self.__handle_host_tracker_HostEvent)

    # called when a link between switches goes up or down 
  def _handle_openflow_discovery_LinkEvent(self, event):
    s1 = dpid_to_str(event.link.dpid1)
    s2 = dpid_to_str(event.link.dpid2)
    if s2 < s1:
        s1, s2 = s2, s1

    if event.added and (s1, s2) not in self.links: 
        log.debug("New link pair: " + s1 + " " + s2) 
        self.links.add((s1, s2))

    elif event.removed and (s1, s2) in self.links:
        log.debug("Tearing down link pair: " + s1 + " " + s2)
        self.links.remove((s1, s2)) 

    # called when an end host connects or disconnects  
    # TODO figure out how to gracefully handle hosts leaving, look at timeouts!
  def __handle_host_tracker_HostEvent(self, event):
    handle = str(event.entry.macaddr)
    if event.join:
        log.debug("Host discovered! " + str(event.entry.macaddr) + " attached to " + dpid_to_str(event.entry.dpid))  
        self.hosts[handle] = dpid_to_str(event.entry.dpid)
    elif event.leave:
        log.debug(handle + " is no longer connected")
        del self.hosts[handle] 

globalstats = [] 
currentstats = []

def handle_stats_in(event):
    log.debug("Got stats from: " + dpid_to_str(event.connection.dpid))
    
    stats = flow_stats_to_list(event.stats)
    for stat in stats:
        if "match" in stat:
            if "dl_src" in stat["match"] and "dl_dst" in stat["match"]:
                stat["holdsource"] = stat["match"]["dl_src"] 
                stat["holddest"] = stat["match"]["dl_dst"] 
            stat["match"] = str(stat["match"])
    global globalstats
    global currentstats
    currentstats = [] 
    for stat in stats:
        if not ("port" in stat["actions"][0] and "OFPP_CONTROLLER" == stat["actions"][0]["port"]):
            globalstats.append(stat) 
            currentstats.append(stat) 
            key = stat["holdsource"] + ":" + stat["holddest"] 
            hub = core.components.get("l2_learning").usage 
            if key not in hub:
                hub[key] = 0
            hub[key] += stat["byte_count"]
            limits = core.components.get("l2_learning").usagecaps 
            if key in limits: 
                if hub[key] >= int(limits[key]):
                    src, dest = stat["holdsource"], stat["holddest"] 
                    msg = of.ofp_flow_mod()
                    msg.priority = 65535
                    msg.match.dl_src = of.EthAddr(src)
                    msg.match.dl_dst = of.EthAddr(dest)
                    msg.actions.append(of.ofp_action_output(port = of.OFPP_NONE)) 
                    for connection in core.openflow.connections.values():
                       connection.send(msg) 
                    log.debug("USAGE CAP MET") 

def launch (transparent=False, hold_down=_flood_delay):
    
  """
  Starts an L2 learning switch.
  """
  try:
    global _flood_delay
    _flood_delay = int(str(hold_down), 10)
    assert _flood_delay >= 0
  except:
    raise RuntimeError("Expected hold-down to be a number")

  core.registerNew(l2_learning, str_to_bool(transparent))

  # this component allows us to keep track of hosts
  core.registerNew(discovery) 
  core.registerNew(host_tracker) 

  core.openflow.addListenerByName("FlowStatsReceived", handle_stats_in)
  app = Bottle() 

  @app.route("/topo") 
  def topo(): 
    switches = list(core.components.get("l2_learning").switches)
    links = list(core.components.get("l2_learning").links)
    hosts = core.components.get("l2_learning").hosts
    usage = core.components.get("l2_learning").usage
    payload = {"switches": switches, "links": links, "hosts": hosts, "usage":usage }
    return json.dumps(payload) 

  @app.route("/stats")
  def statHandler():
    return json.dumps(globalstats)

  @app.route("/current")
  def current():
    return json.dumps(currentstats)

  @app.route("/update")
  def update():
    core.components.get("l2_learning").get_flow_stats()
    return "updated"
  def run():
    try:
        kwargs = {"host": "0.0.0.0", "port": 8080} 
        app.run(**kwargs) 
    except BaseException, e:
        log.error(e.message)
  thread = threading.Thread(target=run)
  thread.daemon = True 
  thread.start() 
