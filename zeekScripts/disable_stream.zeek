# disable-other-logs.zeek

# Disable all default logs
event zeek_init() {
    Log::disable_stream(Weird::LOG);
    Log::disable_stream(DNS::LOG);
    Log::disable_stream(PacketFilter::LOG);
    Log::disable_stream(DHCP::LOG);
    Log::disable_stream(Files::LOG);
    Log::disable_stream(NTP::LOG);
    Log::disable_stream(OCSP::LOG);
    Log::disable_stream(QUIC::LOG);
    Log::disable_stream(HTTP::LOG);
    Log::disable_stream(Reporter::LOG);
    Log::disable_stream(SSL::LOG);
    Log::disable_stream(X509::LOG);
}
