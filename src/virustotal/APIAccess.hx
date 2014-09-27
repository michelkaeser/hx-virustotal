package virustotal;

import haxe.Http;
import virustotal.Response;

/**
 * Abstract base for classes that communicate with the VirusTotal API.
 *
 * Concrete classes should use the perform() method (and not communicate with the API by itself)
 * as it sets the API key etc.
 *
 * @abstract
 */
class APIAccess
{
    /**
     * Stores the base URL used to access the API.
     *
     * @var String
     */
    private static inline var BASE_URL:String = "https://www.virustotal.com/vtapi/v2/";

    /**
     * Stores the VirusTotal API key.
     *
     * @var String
     */
    private var key:String;


    /**
     * Constructor to initialize a new APIAccess instance.
     *
     * @param String key the VirusTotal API key
     */
    private function new(key:String):Void
    {
        this.key = key;
    }

    /**
     * Sends the HTTP request to the API.
     *
     * @param Haxe.Http http the HTTP context to issue the request with
     * @param Bool      post if true, a POST request is performed
     *
     * @return virustotal.Response
     */
    private function sendRequest(http:Http, post:Bool = false):Response
    {
        http.setHeader("Accept", "application/json");
        http.setHeader("Expect", ""); // no Expect 100-continue
        http.setParameter("apikey", this.key);

        var buffer:StringBuf = new StringBuf();
        http.onData = function(data:String):Void
        {
            buffer.addSub(data, 0);
        }
        var _error:Null<String> = null;
        http.onError = function(error:String):Void
        {
            _error = error;
        }
        var _status:Int = 0;
        http.onStatus = function(status:Int):Void
        {
            _status = status;
        }

        http.request(post);

        return new Response(buffer.toString(), _status, _error);
    }
}
