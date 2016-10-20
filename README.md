# \[RFC 3091\]: Pi Digit Generation Protocol

This implements the `pigen` and `pigem` service from [RFC 3091](https://www.ietf.org/rfc/rfc3091.txt) via TCP and UDP. The pigen service is done with a precalculated value of π read from the file "pi" if it exists. If digits beyond the ones available are requested, we violate the "SHOULD" provide an accurate value, and return an approximation consisting of zeros.

The service is deliberately slowed down to 4 answers per second shared among all requestors. Via TCP this results in max 4 characters/sec. Via UDP this may be as high as *max_size_of_udp_packet*\*4. I don't deem this a flooding risk, because you get the same effect with icmp echo's. Nonetheless this may be switched off by commenting the two `&udp_listen()` lines.

## License

Code first released under BSD license 2001-05-01
