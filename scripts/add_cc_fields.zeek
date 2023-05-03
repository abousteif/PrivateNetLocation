@load base/protocols/conn

export {
    redef record Conn::Info += {
        ## The name of the node where this connection was analyzed.
        #node: string &log &optional;

        ## Country code for GeoIP lookup of the originating IP address.
        orig_cc: string &log &optional;

        ## Country code for GeoIP lookup of the responding IP address.
        resp_cc: string &log &optional;
    };
}
