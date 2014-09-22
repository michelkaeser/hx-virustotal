package virustotal;

import haxe.Http;
#if sys
    import lib.io.File;
    import lib.io.FileNotFoundException;
#end
import virustotal.APIAccess;
import virustotal.Response;

#if sys
    using lib.io.FileTools;
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
         * @param lib.io.File file the file to scan
         *
         * @return virustotal.Response
         *
         * @throws lib.io.FileNotFoundException when the file does not exist
         */
        public function submitFile(file:File):Response
        {
            if (file.exists()) {
                var http:Http = new Http("https://www.virustotal.com/vtapi/v2/file/scan");
                http.fileTransfert("file", file.name, file.read(), file.size);

                return this.perform(http);
            }

            throw new FileNotFoundException("File to upload does not exist");
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
        var http:Http = new Http("https://www.virustotal.com/vtapi/v2/url/scan");
        http.setParameter("url", url);

        return this.perform(http);
    }
}
