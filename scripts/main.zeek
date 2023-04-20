#Scripts to use when you want to enrich conn log with location information for RFC1918 networks 
#For Network locations, use localnetdef.db to assign addresses to names

module THETAD;

type Idx: record {
    localnet: subnet;
    };
type Val: record {
    name:string;
    };

global privnet: table[subnet] of Val = table();
redef record Conn::Info += {
    orig_cc:string &log &optional; 
    resp_cc:string &log &optional;
    };

# label what we can
event connection_state_remove(c: connection)
    {
    if ( c$id$orig_h in privnet )
      c$conn$orig_cc = privnet[c$id$orig_h]$name;
    if ( c$id$resp_h in privnet )
      c$conn$resp_cc = privnet[c$id$resp_h]$name;
    }

event zeek_init()
    {
    Input::add_table([
      $source="localnetdef.db",
      $name="privnet",
      $idx=Idx,
      $destination=privnet,
      $val=Val,
      $mode=Input::REREAD]);      
    }
