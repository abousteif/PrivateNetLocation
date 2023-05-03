# @TEST-EXEC: zeek -D -C -r $TRACES/scan_1.pcap ../../../scripts/add_cc_fields ../../../scripts %INPUT
# @TEST-EXEC: zeek-cut id.orig_h id.resp_h orig_cc resp_cc < conn.log > conn.tmp && mv conn.tmp conn.log
# @TEST-EXEC: btest-diff conn.log

@TEST-START-FILE localnetdef.db
#fields	localnet	name
10.0.0.1/32	expected_orig
10.0.0.0/32	expected_resp
@TEST-END-FILE

event zeek_init()
	{
	suspend_processing();
	}

event Input::end_of_data(name: string, source: string)
	{
	if (/localnet/ in source)
		continue_processing();
	}
