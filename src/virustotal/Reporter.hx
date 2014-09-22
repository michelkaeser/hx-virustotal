package virustotal;

import haxe.Http;
import virustotal.APIAccess;
import virustotal.Response;

/**
 * The Reporter class allows one to retrieve results of scheduled/submited
 * scan requests.
 */
class Reporter extends APIAccess
{
    /**
     * Constructor to initialize a new Scanner instance.
     *
     * @param String key the VirusTotal API key
     */
    public function new(key:String):Void
    {
        super(key);
    }

    /**
     * Retrieves the report for the given domain address.
     *
     * @param String domain the domain address to get the report for
     *
     * @return virustotal.Response
     */
    public function retrieveDomainReport(domain:String):Response
    {
        var http:Http = new Http(APIAccess.BASE_URL + "domain/report");
        http.setParameter("domain", domain);

        return this.sendRequest(http);
    }

    /**
     * Retrieves the report for the file scan response.
     *
     * @param virustotal.Response response the scan request response
     *
     * @return virustotal.Response
     */
    public function retrieveFileReport(response:Response):Response
    {
        var http:Http = new Http(APIAccess.BASE_URL + "file/report");
        http.setParameter("resource", response.get("resource"));

        return this.sendRequest(http, true);
    }

    /**
     * Retrieves the report for the given IPv4 address.
     *
     * @param String ip the IPv4 address to get the report for
     *
     * @return virustotal.Response
     */
    public function retrieveIpReport(ip:String):Response
    {
        var http:Http = new Http(APIAccess.BASE_URL + "ip-address/report");
        http.setParameter("ip", ip);

        return this.sendRequest(http);
    }

    /**
     * Retrieves the report for the URL scan response.
     *
     * @param virustotal.Response response the scan request response
     *
     * @return virustotal.Response
     */
    public function retrieveUrlReport(response:Response):Response
    {
        var http:Http = new Http(APIAccess.BASE_URL + "url/report");
        http.setParameter("resource", response.get("resource"));

        return this.sendRequest(http, true);
    }
}
