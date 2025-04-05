## steam-master-server-implementation
Implemented from the protocol description at https://developer.valvesoftware.com/wiki/Master_Server_Query_Protocol

Things that are unimplemented:
- Filtering on gametype, gamedata, gamedataor, name_match, or version_match.
  - The master servers themselves no longer implement `collapse_addr_hash` btw!
- Being tested at all lol.

The wiki's example packets for "joining" the master server don't include the name & gametype, so I didn't bother implementing most of the filters that are related.


## License
AGPL-3.0-or-later because it scares people.
