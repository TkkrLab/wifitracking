# WTR a.k.a. Sekfi
A proof of concept to monitor movement of crowds by analysing 2.4Ghz Wifi devices over time.

**PLEASE NOTE: This project is AbandonWare. **

The project was initiated because we wanted to understand how some Dutch municipalities perform crowd measurements utilising Wifi Tracking. We attempted to approach their methods as closely as possible based on the little information we had, to find out if this was in fact as 'anonymous' as they are telling us.

Also, it is obviously fun to reproduce commercial IoT solutions on shoestring budgets :-)

**WARNING: This software was not intended to ever run production. It could be used to violate peoples privacy. Please don't.**

Our approach uses commodity ESP8266 devices (the catchers) (under 5,- per unit) and some php scripts on a shared webserver. The sensors scan all 2.4Ghz Wifi channels for activity, register client packets, hash them for pseudonimity and once in a while push the hashed data to the server. On the server the hashes are truncated for better anonimity and correlated so a start and stop time for each client in sight of a catcher is registered.

This way we gather 'sessions' of Wifi activity in a certain area. With each catcher it is possible to store geolocation data, which should enable the operator to generate heatmaps over time. Also, in our opinion this method still allows for real 'tracking' because the hashing algorithm does not utilise a catcher specific element. The truncation of hash data still allows for a very small collision rate, allowing people to learn which hash belongs to who. To make this truly anonymous further measures are needed. For instance by adding a salt based on the catcher mac-address and maybe some time factor.

Potential further steps include the above improvements in anonymisation, proper and automated expiration of data, reporting tools like heatmaps etc. and much more.

Even though we were not able to debunk our concerns that Wifitracking is sufficiently anonymous, we decided to not proceed with this project any longer. 