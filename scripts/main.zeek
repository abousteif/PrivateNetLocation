#Scripts to use when you want to enrich conn log with location information for RFC1918 networks
#For Network locations, upload a file to the input framework of the sensor called localnetdef.db to assign addresses to names
#the format shoudl be like this #fields	localnet	name<carriagereturn>192.168.2.0/24<fieldsneedtobetabbed>Washington and so on

module THETAD;

type Idx: record {
	localnet: subnet;
};
type Val: record {
	name: string;
};

global privnet: table[subnet] of string = table();

# label what we can
event connection_state_remove(c: connection)
	{
	if ( c$id$orig_h in privnet )
		c$conn$orig_cc = privnet[c$id$orig_h];
	if ( c$id$resp_h in privnet )
		c$conn$resp_cc = privnet[c$id$resp_h];
	}

event zeek_init()
	{
	Input::add_table([
		$source="localnetdef.db",
		$name="privnet",
		$idx=Idx,
		$destination=privnet,
		$val=Val,
		$mode=Input::REREAD,
		$want_record=F
	]);
	}
