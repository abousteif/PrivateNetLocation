#Scripts to use when you want to enrich conn log with location information for RFC1918 networks
#For Network locations, upload a file to the input framework of the sensor called localnetdef.db to assign addresses to names
#the format should be like this #fields<tab>localnet<tab>name<carriagereturn>192.168.2.0/24<tab>Washington and so on

module THETAD;

type Idx: record {
	localnet: subnet;
};
type Val: record {
	name: string;
};

global privnet: table[subnet] of string = table();

event privnet_input_error(desc: Input::TableDescription, message: string, level: Reporter::Level)
	{
	Reporter::warning(fmt("localnetdef.db: %s", message));
	}

# label what we can - only fill in orig_cc/resp_cc when nothing has set them
# already, so this never clobbers a real GeoIP country code if privnet ever
# ends up with a non-RFC1918 entry.
event connection_state_remove(c: connection)
	{
	if ( ! c$conn?$orig_cc && c$id$orig_h in privnet )
		c$conn$orig_cc = privnet[c$id$orig_h];
	if ( ! c$conn?$resp_cc && c$id$resp_h in privnet )
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
		$want_record=F,
		$error_ev=privnet_input_error
	]);
	}
