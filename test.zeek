global t : table[addr] of set[string];

event http_all_headers(c: connection, is_orig: bool, hlist: mime_header_list)
{
	local agent : string = "null";
	for(qqq in hlist)
	{
		if(hlist[qqq]$name == "USER-AGENT")
		{
			agent = hlist[qqq]$value;
		}
	}
	
	if(agent != "null")
	{
		if ( c$id$orig_h !in t )
		{
			t[c$id$orig_h] = set();
		}
		add t[c$id$orig_h][to_lower(agent)];
	}	
}

event zeek_done()
{
	for(a in t)
	{
		if(|t[a]| >= 3)
		{
			print fmt("%s is a proxy", a);
		}
	}
}
