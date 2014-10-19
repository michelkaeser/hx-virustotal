package virustotal;

import haxe.Http;
#if sys
    import hext.io.File;
    import hext.io.FileNotFoundException;
#end
import virustotal.APIAccess;
import virustotal.Response;

#if sys
    using hext.io.FileTools;
#end

/**
 * The Scanner class allows submitting files, URLs etc. to the VirusTotal API
 * and requests a scan for the given resource.
 */
class Scanner extends APIAccess
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

    #if sys
        /**
         * Submits a scan request for the passed file.
         *
         * @param hext.io.File file the file to scan
         *
         * @return virustotal.Response
         *
         * @throws hext.io.FileNotFoundException when the file does not exist
         */
        public function submitFile(file:File):Response
        {
            if (file.exists()) {
                var http:Http = new Http(APIAccess.BASE_URL + "file/scan");
                http.fileTransfert("file", file.name, file.read(), file.size);

                return this.sendRequest(http, true);
            }

            throw new FileNotFoundException("File to upload does not exist.");
        }
    #end

    /**
     * Submits a scan request for the passed URL.
     *
     * @param String url the URL to scan
     *
     * @return virustotal.Response
     */
    public function submitUrl(url:String):Response
    {
        var http:Http = new Http(APIAccess.BASE_URL + "url/scan");
        http.setParameter("url", url);

        return this.sendRequest(http, true);
    }
}
