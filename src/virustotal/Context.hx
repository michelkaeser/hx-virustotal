package virustotal;

import virustotal.Scanner;
import virustotal.Reporter;

/**
 * The Context class is simply a wrapper around your API key so
 * you don't have to pass it to the Reporter and Scanner one-by-one.
 */
class Context
{
    /**
     * Stores the VirusTotal API key.
     *
     * @var String
     */
    private var key:String;


    /**
     * Constructor to initialize a new Context instance.
     *
     * @param String key the VirusTotal API key
     */
    public function new(key:String):Void
    {
        this.key = key;
    }

    /**
     * Returns a Reporter that can be used to get scan results.
     *
     * @return virustotal.Reporter
     */
    public function getReporter():Reporter
    {
        return new Reporter(this.key);
    }

    /**
     * Returns a Scanner instance that can be used to submit scan requests.
     *
     * @return virustotal.Scanner
     */
    public function getScanner():Scanner
    {
        return new Scanner(this.key);
    }
}
