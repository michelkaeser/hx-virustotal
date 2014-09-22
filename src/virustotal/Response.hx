package virustotal;

import haxe.Json;

/**
 * VirusTotal API call response wrapper class.
 */
class Response
{
    /**
     * Stores the data returned by an API call.
     *
     * @var Null<haxe.Json>
     */
    public var data(default, null):Null<Json>;

    /**
     * Stores the error message returned by the API call.
     *
     * @var Null<String>
     */
    public var error(default, null):Null<String>;

    /**
     * Stores the status code returned by the API call.
     *
     * @var Int
     */
    public var status(default, null):Int;


    /**
     * Constructor to initialize a new Response instance.
     *
     * @var Null<String> data   the response data
     * @var Int          status the response's status code
     * @var Null<String> error  an optional error message
     */
    public function new(data:Null<String>, status:Int, error:Null<String>):Void
    {
        if (data == null) {
            this.data = null;
        } else {
            this.data = Json.parse(data);
        }
        this.status = status;
        this.error  = error;
    }

    /**
     * Returns the field named 'field' from the encapsulated response.
     *
     * @param String field the field to get
     *
     * @return Null<String> the field's value
     */
    public function get(field:String):Null<String>
    {
        if (this.data != null) {
            return Reflect.field(this.data, field);
        }

        return null;
    }
}
