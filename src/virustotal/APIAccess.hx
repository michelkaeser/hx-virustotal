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
     * Performs an API access request.
     *
     * @param Haxe.Http http the HTTP context to issue the request with
     *
     * @return virustotal.Response
     */
    private function perform(http:Http):Response
    {
        http.setParameter("apikey", this.key);

        var response = { data: null, status: 0, error: null };
        http.onData = function(data:String):Void
        {
            response.data = data;
        }
        http.onError = function(error:String):Void
        {
            response.error = error;
        }
        http.onStatus = function(status:Int):Void
        {
            response.status = status;
        }
        http.request(true);

        return new Response(response.data, response.status, response.error);
    }
}
