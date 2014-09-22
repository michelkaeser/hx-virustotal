package virustotal;

/**
 * VirusTotal API 'response_code' codes.
 *
 * @link https://www.virustotal.com/de/documentation/public-api/#response-basics
 */
@:enum
abstract ResponseCode(Int) from Int to Int
{
    var QUEUED      = -2;
    var NOT_PRESENT =  0;
    var PRESENT     =  1;
}
