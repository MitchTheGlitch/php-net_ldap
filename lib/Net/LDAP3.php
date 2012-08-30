<?php
/*
 +-----------------------------------------------------------------------+
 | Net/LDAP3.php                                                         |
 |                                                                       |
 | Based on rcube_ldap_generic.php created by the Roundcube Webmail      |
 | client development team.                                              |
 |                                                                       |
 | Copyright (C) 2006-2012, The Roundcube Dev Team                       |
 | Copyright (C) 2012, Kolab Systems AG                                  |
 |                                                                       |
 | Licensed under the GNU General Public License version 3 or            |
 | any later version with exceptions for plugins.                        |
 | See the README file for a full license statement.                     |
 |                                                                       |
 | PURPOSE:                                                              |
 |   Provide advanced functionality for accessing LDAP directories       |
 |                                                                       |
 +-----------------------------------------------------------------------+
 | Authors: Thomas Bruederli <roundcube@gmail.com>                       |
 |          Aleksander Machniak <machniak@kolabsys.com>                  |
 |          Jeroen van Meeuwen <vanmeeuwen@kolabsys.com>                 |
 +-----------------------------------------------------------------------+
*/

require_once('PEAR.php');
require_once('LDAP3/Result.php');

/**
 * Model class to access a LDAP directories
 *
 * @package Net_LDAP3
 */
class Net_LDAP3
{
    const UPDATE_MOD_ADD = 1;
    const UPDATE_MOD_DELETE = 2;
    const UPDATE_MOD_REPLACE = 4;
    const UPDATE_MOD_FULL = 7;

    private $conn;
    public $vlv_active = FALSE;

    protected $config = Array(
            'sizelimit' => 0,
            'timelimit' => 0,
            'vlv' => NULL
        );

    private $attribute_level_rights_map = array(
            "r" => "read",
            "s" => "search",
            "w" => "write",
            "o" => "delete",
            "c" => "compare",
            "W" => "write",
            "O" => "delete"
        );

    private $entry_level_rights_map = array(
            "a" => "add",
            "d" => "delete",
            "n" => "modrdn",
            "v" => "read"
        );

    /*
        Manipulate configuration through the config_set and config_get methods.
    *//*
            'debug' => FALSE,
            'host' => NULL,
            'hosts' => Array(),
            'port' => 389,
            'use_tls' => FALSE,
            'bind_dn' => '%bind_dn',
            'bind_pw' => '%bind_pw',
            'service_bind_dn' => 'uid=kolab-service,ou=Special Users,dc=example,dc=org',
            'service_bind_pw' => 'Welcome2KolabSystems',
            'root_dn' => 'dc=example,dc=org',
            'root_dn_db_name' => 'example_org',
            'root_dn_db_name_attr' => 'cn',
            'config_root_dn' => 'cn=config',
            'sizelimit' => 0,
            'timelimit' => 0,
            // Force VLV off.
            'vlv' => FALSE,

        );
    */

    protected $return_attributes = Array('entrydn');
    protected $entries = NULL;
    protected $result = NULL;
    protected $debug_level = FALSE;
    protected $list_page = 1;
    protected $page_size = 10;

    // Use public method config_set('log_hook', $callback) to have $callback be
    // call_user_func'ed instead of the local log functions.
    protected $_log_hook = NULL;

    // Use public method config_set('config_get_hook', $callback) to have
    // $callback be call_user_func'ed instead of the local config_get function.
    protected $_config_get_hook = NULL;

    // Use public method config_set('config_set_hook', $callback) to have
    // $callback be call_user_func'ed instead of the local config_set function.
    protected $_config_set_hook = NULL;

    // Not Yet Implemented
    // Intended to allow hooking in for the purpose of caching.
    protected $_result_hook = NULL;

    // Runtime. These are not the variables you're looking for.
    protected $_current_bind_dn = NULL;
    protected $_current_host = NULL;
    protected $_supported_control = Array();
    protected $_vlv_indexes_and_searches = NULL;

    /**
     * Constructor
     *
     * @param   array   $config Configuration parameters that have not already
     *                          been initialized. For configuration parameters
     *                          that have in fact been set, use the config_set()
     *                          method after initialization.
     */
    public function __construct($config = Array()) {
        Log::trace("Net_LDAP3 being constructed");
        if (!empty($config) && is_array($config)) {
            foreach ($config as $key => $value) {
                if (!isset($this->config[$key]) || empty($this->config[$key])) {
                    $this->config[$key] = $value;
                }
            }
        }
    }

    /**
     *  Add multiple entries to the directory information tree in one go.
     */
    public function add_entries($entries, $attributes = Array()) {
        // If $entries is an associative array, it's keys are DNs and it's
        // values are the attributes for that DN.
        //
        // If $entries is a non-associative array, the attributes are expected
        // to be positional in $attributes.

        $result_set = Array();

        if (array_keys($entries) == range(0, count($entries) - 1)) {
            // $entries is sequential

            if (count($entries) !== count($attributes)) {
                new PEAR_Error("Wrong entry/attribute count in " . __FUNCTION__);
                return FALSE;
            }

            for ($i = 0; $i < count($entries); $i++) {
                $result_set[$i] = $this->add_entry(
                        $entries[$i],
                        $attributes[$i]
                    );

            }
        } else {
            // $entries is associative
            foreach ($entries as $entry_dn => $entry_attributes) {
                if (array_keys($attributes) !== range(0,count($attributes)-1)) {
                    // $attributes is associative as well, let's merge these
                    //
                    // $entry_attributes takes precedence, so is in the second
                    // position in array_merge()
                    $entry_attributes = array_merge(
                            $attributes,
                            $entry_attributes
                        );

                }

                $result_set[$entry_dn] = $this->add_entry(
                        $entry_dn,
                        $entry_attributes
                    );
            }
        }

        return $result_set;

    }

    /**
     * Add an entry to the directory information tree.
     */
    public function add_entry($entry_dn, $attributes)
    {
        // TODO:
        // - Get entry rdn attribute value from entry_dn and see if it exists in
        //   attributes -> issue warning if so (but not block the operation).
        $this->_debug("Entry DN", $entry_dn);
        $this->_debug("Attributes", $attributes);

        foreach ($attributes as $attr_name => $attr_value) {
            if (empty($attr_value)) {
                unset($attributes[$attr_name]);
            }
        }

        $this->_debug("C: Add $entry_dn: " . json_encode($attributes));

        if (($add_result = ldap_add($this->conn, $entry_dn, $attributes)) == FALSE) {
            $this->_debug("S: " . ldap_error($this->conn));
            $this->_debug("S: Adding entry $entry_dn failed. " . ldap_error($this->conn));

            return FALSE;
        }

        $this->_debug("LDAP: S: OK");

        return TRUE;
    }

    public function attribute_details($attributes = array())
    {
        $_schema = $this->init_schema();

        $attribs = $_schema->getAll('attributes');

        $attributes_details = array();

        foreach ($attributes as $attribute) {
            if (array_key_exists($attribute, $attribs)) {
                $attrib_details = $attribs[$attribute];

                if (!empty($attrib_details['sup'])) {
                    foreach ($attrib_details['sup'] as $super_attrib) {
                        $_attrib_details = $attribs[$super_attrib];
                        if (is_array($_attrib_details)) {
                            $attrib_details = array_merge($_attrib_details, $attrib_details);
                        }
                    }
                }
            } else if (array_key_exists(strtolower($attribute), $attribs)) {
                $attrib_details = $attribs[strtolower($attribute)];

                if (!empty($attrib_details['sup'])) {
                    foreach ($attrib_details['sup'] as $super_attrib) {
                        $_attrib_details = $attribs[$super_attrib];
                        if (is_array($_attrib_details)) {
                            $attrib_details = array_merge($_attrib_details, $attrib_details);
                        }
                    }
                }
            } else {
                Log::warning("LDAP: No schema details exist for attribute $attribute (which is strange)");
            }

            // The relevant parts only, please
            $attributes_details[$attribute] = array(
                'type' => (array_key_exists('single-value', $attrib_details) && $attrib_details['single-value']) ? "text" : "list",
                'description' => $attrib_details['desc'],
                'syntax' => $attrib_details['syntax'],
                'max-length' => (array_key_exists('max_length', $attrib_details)) ? $attrib_details['max-length'] : FALSE,
            );
        }

        return $attributes_details;
    }

    public function attributes_allowed($objectclasses = array())
    {
        $this->_debug("Listing allowed_attributes for objectclasses", $objectclasses);

        if (!is_array($objectclasses)) {
            return FALSE;
        }

        if (empty($objectclasses)) {
            return FALSE;
        }

        $schema       = $this->init_schema();
        $may          = array();
        $must         = array();
        $superclasses = array();

        foreach ($objectclasses as $objectclass) {
            $superclass = $schema->superclass($objectclass);
            if (!empty($superclass)) {
                $superclasses = array_merge($superclass, $superclasses);
            }

            $_may = $schema->may($objectclass);
            if (is_array($_may)) {
                $may = array_merge($may, $_may);
            } /* else {
            } */
            $_must = $schema->must($objectclass);
            if (is_array($_must)) {
                $must = array_merge($must, $_must);
            } /* else {
                var_dump($_must);
            } */
        }

        return array('may' => $may, 'must' => $must, 'super' => $superclasses);

    }

    /**
     * Bind connection with DN and password
     *
     * @param string $dn   Bind DN
     * @param string $pass Bind password
     *
     * @return boolean True on success, False on error
     */
    public function bind($bind_dn, $bind_pw)
    {
        if (!$this->conn) {
            return FALSE;
        }

        if ($bind_dn == $this->_current_bind_dn) {
            return TRUE;
        }

        $this->_debug("C: Bind [dn: $bind_dn] [pass: $bind_pw]");

        if (@ldap_bind($this->conn, $bind_dn, $bind_pw)) {
            $this->_debug("S: OK");
            $this->_current_bind_dn = $bind_dn;
            return TRUE;
        }

        $this->_debug("S: ".ldap_error($this->conn));

        new PEAR_Error("Bind failed for dn=$bind_dn: ".ldap_error($this->conn), ldap_errno($this->conn));
        return FALSE;
    }

    /**
     * Close connection to LDAP server
     */
    public function close()
    {
        if ($this->conn) {
            $this->_debug("C: Close");
            ldap_unbind($this->conn);
            $this->conn = NULL;
        }
    }

    /**
     *  Get the value of a configuration item.
     *
     *  @param  string  $key        Configuration key
     *  @param  mixed   $default    Default value to return
     */
    public function config_get($key, $default = NULL) {
        if (!empty($this->_config_get_hook)) {
            return call_user_func_array($this->_config_get_hook, Array($key, $value));
        } else if (method_exists($this, "config_get_{$key}")) {
            return call_user_func(array($this, "config_get_$key"), $value);
        } else if (!isset($this->config[$key])) {
            return $default;
        } else {
            return $this->config[$key];
        }
    }

    /**
     *  Set a configuration item to value.
     *
     *  @param string  $key        Configuration key
     *  @param mixed   $value      Configuration value
     */
    public function config_set($key, $value) {
        if (!empty($this->_config_set_hook)) {
            return call_user_func(
                    $this->_config_set_hook,
                    Array($key, $value)
                );

        } else if (method_exists($this, "config_set_{$key}")) {
            return call_user_func_array(
                    Array($this, "config_set_$key"),
                    Array($value)
                );

        } else if (isset($this->$key)) {
            $this->_debug("setting property $key to value " . var_export($value, TRUE));
            $this->$key = $value;
        } else {
            $this->_debug("setting config array $key to value " . var_export($value, TRUE));
            $this->config[$key] = $value;
        }
    }

    /**
     *  Establish a connection to the LDAP server
     */
    public function connect()
    {
        Log::trace("Net_LDAP3 connecting");

        if (!function_exists('ldap_connect')) {
            new PEAR_Error("No ldap support in this PHP installation", 100);
            return FALSE;
        }

        if (is_resource($this->conn)) {
            $this->_debug("Connection already exists");
            return TRUE;
        }

        $config_hosts = $this->config_get('hosts', Array());
        $config_host = $this->config_get('host', NULL);

        if (empty($config_hosts)) {
            if (empty($config_host)) {
                new PEAR_Error("No host or hosts configured", __LINE__);
                return FALSE;
            }

            $this->config_set('hosts', Array($this->config_get('host')));
        }

        $port = $this->config_get('port', 389);

        foreach ($this->config_get('hosts') as $host) {
            $this->_debug("C: Connect [$host:$port]");

            if ($lc = @ldap_connect($host, $port))
            {
                if ($this->config_get('use_tls', FALSE) === TRUE) {
                    if (!ldap_start_tls($lc)) {
                        $this->_debug("S: Could not start TLS.");
                        continue;
                    }
                }

                $this->_debug("S: OK");

                ldap_set_option(
                        $lc,
                        LDAP_OPT_PROTOCOL_VERSION,
                        $this->config_get('ldap_version', 3)
                    );

                $this->_current_host = $host;
                $this->conn = $lc;

                if ($this->config_get('referrals', FALSE)) {
                    ldap_set_option(
                            $lc,
                            LDAP_OPT_REFERRALS,
                            $this->config['referrals']
                        );
                }

                break;
            }

            $this->_debug("S: NOT OK");
        }

        if (!is_resource($this->conn)) {
            new PEAR_Error("Could not connect to LDAP", 100);
            return FALSE;
        }

        return TRUE;
    }

    /**
     *   Shortcut to ldap_delete()
     */
    public function delete_entry($entry_dn)
    {
        $this->_debug("LDAP: C: Delete $entry_dn");

        if (ldap_delete($this->conn, $entry_dn) === FALSE) {
            $this->_debug("LDAP: S: " . ldap_error($this->conn));
            $this->_debug("LDAP: Delete failed. " . ldap_error($this->conn));
            return FALSE;
        }

        $this->_debug("LDAP: S: OK");

        return TRUE;
    }

    public function effective_rights($subject)
    {
        $effective_rights_control_oid = "1.3.6.1.4.1.42.2.27.9.5.2";

        $supported_controls = $this->supported_controls();

        if (!in_array($effective_rights_control_oid, $supported_controls)) {
            $this->_debug("LDAP: No getEffectiveRights control in supportedControls");
            return $this->legacy_rights($subject);
        }

        $attributes = array(
            'attributeLevelRights' => array(),
            'entryLevelRights' => array(),
        );

        $output   = array();
        $entry_dn = $this->entry_dn($subject);

        if (!$entry_dn) {
            $entry_dn = $this->config_get($subject . "_base_dn");
        }
        if (!$entry_dn) {
            $entry_dn = $this->config_get("base_dn");
        }

        $this->_debug("effective_rights for subject $subject resolves to entry dn $entry_dn");

        $moz_ldapsearch = "/usr/lib64/mozldap/ldapsearch";
        if (!is_file($moz_ldapsearch)) {
            $moz_ldapsearch = "/usr/lib/mozldap/ldapsearch";
        }
        if (!is_file($moz_ldapsearch)) {
            $moz_ldapsearch = NULL;
        }

        if (empty($moz_ldapsearch)) {
            $this->_debug("Mozilla LDAP C SDK binary ldapsearch not found, cannot get effective rights on subject $subject");
            return NULL;
        }

        $command = array(
                $moz_ldapsearch,
                '-x',
                '-h',
                $this->_ldap_server,
                '-p',
                $this->_ldap_port,
                '-b',
                escapeshellarg($entry_dn),
                '-D',
                escapeshellarg($_SESSION['user']->user_bind_dn),
                '-w',
                escapeshellarg($_SESSION['user']->user_bind_pw),
                '-J',
                escapeshellarg(implode(':', array(
                    $effective_rights_control_oid,          // OID
                    'TRUE',                                 // Criticality
                    'dn:' . $_SESSION['user']->user_bind_dn // User DN
                ))),
                '-s',
                'base',
                '"(objectclass=*)"',
                '"*"',
            );

        $command = implode(' ', $command);

        $this->_debug("LDAP: Executing command: $command");

        exec($command, $output, $return_code);

        $this->_debug("LDAP: Command output:" . var_export($output, TRUE));
        $this->_debug("Return code: " . $return_code);

        $lines = array();
        foreach ($output as $line_num => $line) {
            if (substr($line, 0, 1) == " ") {
                $lines[count($lines)-1] .= trim($line);
            } else {
                $lines[] = trim($line);
            }
        }

        foreach ($lines as $line) {
            $line_components = explode(':', $line);
            $attribute_name = array_shift($line_components);
            $attribute_value = trim(implode(':', $line_components));

            switch ($attribute_name) {
                case "attributeLevelRights":
                    $attributes[$attribute_name] = $this->parse_attribute_level_rights($attribute_value);
                    break;
                case "dn":
                    $attributes[$attribute_name] = $attribute_value;
                    break;
                case "entryLevelRights":
                    $attributes[$attribute_name] = $this->parse_entry_level_rights($attribute_value);
                    break;

                default:
                    break;
            }
        }

        return $attributes;
    }

    public function entry_dn($subject)
    {
        $this->_debug("entry_dn on subject $subject");
        $is_dn = ldap_explode_dn($subject, 1);
        $this->_debug($is_dn ? "entry_dn is a dn" : "entry_dn is not a dn");

        if (is_array($is_dn) && array_key_exists("count", $is_dn) && $is_dn["count"] > 0) {
            return $subject;
        }

        $unique_attr = $this->config_get('unique_attribute', 'nsuniqueid');
        $subject     = $this->entry_find_by_attribute(array($unique_attr => $subject));

        if (!empty($subject)) {
            return key($subject);
        }
    }

    public function entry_find_by_attribute($attributes, $base_dn = NULL)
    {
        $this->_debug("Auth::LDAP::entry_find_by_attribute(\$attributes, \$base_dn) called with base_dn", $base_dn, "and attributes", $attributes);

        if (empty($attributes) || !is_array($attributes)) {
            return FALSE;
        }

        if (empty($attributes[key($attributes)])) {
            return FALSE;
        }

        $filter = "(&";

        foreach ($attributes as $key => $value) {
            $filter .= "(" . $key . "=" . $value . ")";
        }

        $filter .= ")";

        if (empty($base_dn)) {
            $base_dn = $this->config_get('root_dn');
            $this->_debug("Using base_dn from domain " . $this->domain . ": " . $base_dn);
        }

        $this->config_set('return_attributes', array_keys($attributes));
        $result = $this->search($base_dn, $filter);

        if ($result->count() > 0) {
            $this->_debug("Results found: " . implode(', ', array_keys($result->entries(TRUE))));
            return $result->entries(TRUE);
        }
        else {
            $this->_debug("No result");
            return FALSE;
        }
    }

    public function find_user_groups($member_dn)
    {
        $this->_debug(__FILE__ . "(" . __LINE__ . "): " .  $member_dn);

        $groups  = array();
        $root_dn = $this->domain_root_dn($this->domain);

        // TODO: Do not query for both, it's either one or the other
        $entries = $this->search($root_dn, "(|" .
            "(&(objectclass=groupofnames)(member=$member_dn))" .
            "(&(objectclass=groupofuniquenames)(uniquemember=$member_dn))" .
            ")");

        $groups  = array_keys($entries);

        return $groups;
    }

    public function get_entry_attribute($subject_dn, $attribute)
    {
        $this->config_set('return_attributes', $attributes);
        $result = $this->search($subject_dn, '(objectclass=*)', 'base');
        $dn     = key($result);
        $attr   = key($result[$dn]);

        return $result[$dn][$attr];
    }

    public function get_entry_attributes($subject_dn, $attributes)
    {
        $this->config_set('return_attributes', $attributes);
        $entries = $this->search($subject_dn, '(objectclass=*)', 'base');
        $entry = $entries->entries(TRUE);
        $result = $entry[0];

        if (!empty($result)) {
            $result = array_pop($result);
            return $result;
        }

        return FALSE;
    }

    /*
        Get the total number of entries.
    */
    public function get_count($base_dn, $filter = '(objectclass=*)', $scope = 'sub')
    {
        if (!$this->__result_current($base_dn, $filter, $scope)) {
            new PEAR_Error("No current search result for these search parameters");
            return FALSE;
        }

        return $this->result->get_total();
    }

    /**
     * Get a specific LDAP entry, identified by its DN
     *
     * @param string $dn Record identifier
     * @return array     Hash array
     */
    public function get_entry($dn)
    {
        $rec = NULL;

        if ($this->conn && $dn) {
            $this->_debug("C: Read [dn: $dn] [(objectclass=*)]");

            if ($ldap_result = @ldap_read($this->conn, $dn, '(objectclass=*)', $this->return_attributes)) {
                $this->_debug("S: OK");

                if ($entry = ldap_first_entry($this->conn, $ldap_result)) {
                    $rec = ldap_get_attributes($this->conn, $entry);
                }
            }
            else {
                $this->_debug("S: ".ldap_error($this->conn));
            }

            if (!empty($rec)) {
                $rec['dn'] = $dn; // Add in the dn for the entry.
            }
        }

        return $rec;
    }

    /**
     * Return the last result set
     *
     * @return object rcube_ldap_result Result object
     */
    public function get_result()
    {
        return $this->result;
    }

    public function login($username, $password) {
        $_bind_dn = $this->config_get('service_bind_dn');
        $_bind_pw = $this->config_get('service_bind_pw');

        if (empty($_bind_dn)) {
            new PEAR_Error("No valid service bind dn found.");
            $this->_debug("No valid service bind dn found.");
            return NULL;
        }

        if (empty($_bind_pw)) {
            new PEAR_Error("No valid service bind password found.");
            $this->_debug("No valid service bind password found.");
            return NULL;
        }

        $bound = $this->bind($_bind_dn, $_bind_pw);

        if (!$bound) {
            new PEAR_Error("Could not bind with service bind credentials.");
            $this->_debug("Could not bind with service bind credentials.");
            return NULL;
        }

        $entry_dn = $this->entry_dn($username);

        if (!empty($entry_dn)) {
            $bound = $this->bind($entry_dn, $password);

            if (!$bound) {
                new PEAR_Error("Could not bind with " . $entry_dn);
                return NULL;
            }

            return $entry_dn;
        }

        $base_dn = $this->config_get('root_dn');

        if (empty($base_dn)) {
            new PEAR_Error("Could not get a valid base dn to search.");
            $this->_debug("Could not get a valid base dn to search.");
            return NULL;
        }

        if (count(explode('@', $username)) > 1) {
            $__parts = explode('@', $username);
            $localpart = $__parts[0];
            $domain = $__parts[1];
        } else {
            $localpart = $username;
            $domain = '';
        }

        $realm = $domain;

        $filter = $this->config_get("login_filter", NULL);
        if (empty($filter)) {
            $filter = $this->config_get("filter", NULL);
        }
        if (empty($filter)) {
            $filter = "(&(|(mail=%s)(alias=%s)(uid=%s))(objectclass=inetorgperson))";
        }

        $this->_debug("Net::LDAP3::login() original filter: " . $filter);

        $replace_patterns = Array(
                '/%s/' => $username,
                '/%d/' => $domain,
                '/%U/' => $localpart,
                '/%r/' => $realm
            );

        $filter = preg_replace(array_keys($replace_patterns), array_values($replace_patterns), $filter);

        $this->_debug("Net::LDAP3::login() actual filter: " . $filter);

        $result = $this->search($base_dn, $filter, 'sub');

        if (!$result) {
            new PEAR_Error("Could not search $base_dn with $filter");
        }

        if ($this->result->count() > 1) {
            new PEAR_Error("Multiple entries found.");
            return NULL;
        } else if ($this->result->count() < 1) {
            new PEAR_Error("No entries found.");
            return NULL;
        }

        $entries = $this->result->entries();
        $entry = self::normalize_result($entries);
        $entry_dn = key($entry);

        $bound = $this->bind($entry_dn, $password);

        if (!$bound) {
            new PEAR_Error("Could not bind with " . $entry_dn);
            return NULL;
        }

        return $entry_dn;
    }

    public function list_entries($base_dn, $filter = '(objectclass=*)', $scope = 'sub', $sort = NULL)
    {
        $search = $this->search($base_dn, $filter, $scope, $sort);

        if (!$search) {
            $this->_debug("Net_LDAP3: Search did not succeed!");
            return FALSE;
        }

        return $this->result;

    }

    public function list_group_members($dn, $entry = NULL, $recurse = TRUE)
    {
        $group_members = array();

        if (is_array($entry) && in_array('objectclass', $entry)) {
            if (!in_array(array('groupofnames', 'groupofuniquenames', 'groupofurls'), $entry['objectclass'])) {
                $this->_debug("Called _list_groups_members on a non-group!");
            }
            else {
                $this->_debug("Called list_group_members(" . $dn . ")");
            }
        }

        $entry = $this->search($dn);

        $this->_debug("ENTRIES for \$dn $dn", $entry);

        foreach ($entry[$dn] as $attribute => $value) {
            if ($attribute == "objectclass") {
                foreach ($value as $objectclass) {
                    switch (strtolower($objectclass)) {
                        case "groupofnames":
                        case "kolabgroupofnames":
                            $group_members = array_merge($group_members, $this->_list_group_member($dn, $entry[$dn]['member'], $recurse));
                            break;
                        case "groupofuniquenames":
                        case "kolabgroupofuniquenames":
                            $group_members = array_merge($group_members, $this->_list_group_uniquemember($dn, $entry[$dn]['uniquemember'], $recurse));
                            break;
                        case "groupofurls":
                            $group_members = array_merge($group_members, $this->_list_group_memberurl($dn, $entry[$dn]['memberurl'], $recurse));
                            break;
                    }
                }
            }
        }

        return array_filter($group_members);
    }

    public function modify_entry($subject_dn, $old_attrs, $new_attrs)
    {
        $this->_debug("OLD ATTRIBUTES", $old_attrs);
        $this->_debug("NEW ATTRIBUTES", $new_attrs);

        // TODO: Get $rdn_attr - we have type_id in $new_attrs
        $dn_components  = ldap_explode_dn($subject_dn, 0);
        $rdn_components = explode('=', $dn_components[0]);

        $rdn_attr = $rdn_components[0];

        $this->_debug("Auth::LDAP::modify_entry() using rdn attribute: " . $rdn_attr);

        $mod_array = array(
            'add'       => array(), // For use with ldap_mod_add()
            'del'       => array(), // For use with ldap_mod_del()
            'replace'   => array(), // For use with ldap_mod_replace()
            'rename'    => array(), // For use with ldap_rename()
        );

        // This is me cheating. Remove this special attribute.
        if (array_key_exists('ou', $old_attrs) || array_key_exists('ou', $new_attrs)) {
            $old_ou = $old_attrs['ou'];
            $new_ou = $new_attrs['ou'];
            unset($old_attrs['ou']);
            unset($new_attrs['ou']);
        } else {
            $old_ou = NULL;
            $new_ou = NULL;
        }

        // Compare each attribute value of the old attrs with the corresponding value
        // in the new attrs, if any.
        foreach ($old_attrs as $attr => $old_attr_value) {

            if (array_key_exists($attr, $new_attrs)) {
                if (is_array($old_attrs[$attr]) && is_array($new_attrs[$attr])) {
                    $_sort1 = $new_attrs[$attr];
                    sort($_sort1);
                    $_sort2 = $old_attr_value;
                    sort($_sort2);
                } else {
                    $_sort1 = TRUE;
                    $_sort2 = FALSE;
                }

                if (!($new_attrs[$attr] === $old_attr_value) && !($_sort1 === $_sort2)) {
                    $this->_debug("Attribute $attr changed from", $old_attr_value, "to", $new_attrs[$attr]);
                    if ($attr === $rdn_attr) {
                        $this->_debug("This attribute is the RDN attribute. Let's see if it is multi-valued, and if the original still exists in the new value.");
                        if (is_array($old_attrs[$attr])) {
                            if (!is_array($new_attrs[$attr])) {
                                if (in_array($new_attrs[$attr], $old_attrs[$attr])) {
                                    // TODO: Need to remove all $old_attrs[$attr] values not equal to $new_attrs[$attr], and not equal to the current $rdn_attr value [0]

                                    $this->_debug("old attrs. is array, new attrs. is not array. new attr. exists in old attrs.");

                                    $rdn_attr_value = array_shift($old_attrs[$attr]);
                                    $_attr_to_remove = array();

                                    foreach ($old_attrs[$attr] as $value) {
                                        if (strtolower($value) != strtolower($new_attrs[$attr])) {
                                            $_attr_to_remove[] = $value;
                                        }
                                    }

                                    $this->_debug("Adding to delete attribute $attr values:" . implode(', ', $_attr_to_remove));

                                    $mod_array['delete'][$attr] = $_attr_to_remove;

                                    if (strtolower($new_attrs[$attr]) !== strtolower($rdn_attr_value)) {
                                        $this->_debug("new attrs is not the same as the old rdn value, issuing a rename");
                                        $mod_array['rename']['dn'] = $subject_dn;
                                        $mod_array['rename']['new_rdn'] = $rdn_attr . '=' . $new_attrs[$attr][0];
                                    }

                                } else {
                                    $this->_debug("new attrs is not the same as any of the old rdn value, issuing a full rename");
                                    $mod_array['rename']['dn'] = $subject_dn;
                                    $mod_array['rename']['new_rdn'] = $rdn_attr . '=' . $new_attrs[$attr];
                                }
                            } else {
                                // TODO: See if the rdn attr. value is still in $new_attrs[$attr]
                                if (in_array($old_attrs[$attr][0], $new_attrs[$attr])) {
                                    $this->_debug("Simply replacing attr $attr as rnd attr value is preserved.");
                                    $mod_array['replace'][$attr] = $new_attrs[$attr];
                                } else {
                                    // TODO: This fails.
                                    $mod_array['rename']['dn'] = $subject_dn;
                                    $mod_array['rename']['new_rdn'] = $rdn_attr . '=' . $new_attrs[$attr][0];
                                    $mod_array['delete'][$attr] = $old_attrs[$attr][0];
                                }
                            }
                        } else {
                            if (!is_array($new_attrs[$attr])) {
                                $this->_debug("Renaming " . $old_attrs[$attr] . " to " . $new_attrs[$attr]);
                                $mod_array['rename']['dn'] = $subject_dn;
                                $mod_array['rename']['new_rdn'] = $rdn_attr . '=' . $new_attrs[$attr];
                            } else {
                                $this->_debug("Adding to replace");
                                // An additional attribute value is being supplied. Just replace and continue.
                                $mod_array['replace'][$attr] = $new_attrs[$attr];
                                continue;
                            }
                        }

                    } else {
                        if (empty($new_attrs[$attr])) {
                            switch ($attr) {
                                case "userpassword":
                                    break;
                                default:
                                    $this->_debug("Adding to del: $attr");
                                    $mod_array['del'][$attr] = (array)($old_attr_value);
                                    break;
                            }
                        } else {
                            $this->_debug("Adding to replace: $attr");
                            $mod_array['replace'][$attr] = (array)($new_attrs[$attr]);
                        }
                    }
                } else {
                    $this->_debug("Attribute $attr unchanged");
                }
            } else {
                // TODO: Since we're not shipping the entire object back and forth, and only post
                // part of the data... we don't know what is actually removed (think modifiedtimestamp, etc.)
                $this->_debug("Group attribute $attr not mentioned in \$new_attrs..., but not explicitly removed... by assumption");
            }
        }

        foreach ($new_attrs as $attr => $value) {
            if (array_key_exists($attr, $old_attrs)) {
                if (empty($value)) {
                    if (!array_key_exists($attr, $mod_array['del'])) {
                        switch ($attr) {
                            case 'userpassword':
                                break;
                            default:
                                $this->_debug("Adding to del(2): $attr");
                                $mod_array['del'][$attr] = (array)($old_attrs[$attr]);
                                break;
                        }
                    }
                } else {
                    if (!($old_attrs[$attr] === $value) && !($attr === $rdn_attr)) {
                        if (!array_key_exists($attr, $mod_array['replace'])) {
                            $this->_debug("Adding to replace(2): $attr");
                            $mod_array['replace'][$attr] = $value;
                        }
                    }
                }
            } else {
                if (!empty($value)) {
                    $mod_array['add'][$attr] = $value;
                }
            }
        }

        if (empty($old_ou)) {
            $subject_dn_components = ldap_explode_dn($subject_dn, 0);
            unset($subject_dn_components["count"]);
            $subject_rdn = array_shift($subject_dn_components);
            $old_ou = implode(',', $subject_dn_components);
        }

        if (!(empty($old_ou) || empty($new_ou)) && !(strtolower($old_ou) === strtolower($new_ou))) {
            $mod_array['rename']['new_parent'] = $new_ou;
            if (empty($mod_array['rename']['dn']) || empty($mod_array['rename']['new_rdn'])) {
                $mod_array['rename']['dn'] = $subject_dn;
                $mod_array['rename']['new_rdn'] = $rdn_attr . '=' . $new_attrs[$rdn_attr];
            }
        }

        $this->_debug($mod_array);

        $result = $this->modify_entry_attributes($subject_dn, $mod_array);

        if ($result) {
            return $mod_array;
        }

    }

    /**
     * Bind connection with (SASL-) user and password
     *
     * @param string $authc Authentication user
     * @param string $pass  Bind password
     * @param string $authz Autorization user
     *
     * @return boolean True on success, False on error
     */
    public function sasl_bind($authc, $pass, $authz=NULL)
    {
        if (!$this->conn) {
            return FALSE;
        }

        if (!function_exists('ldap_sasl_bind')) {
            new PEAR_Error("Unable to bind: ldap_sasl_bind() not exists", 100);
            return FALSE;
        }

        if (!empty($authz)) {
            $authz = 'u:' . $authz;
        }

        if (!empty($this->config['auth_method'])) {
            $method = $this->config['auth_method'];
        }
        else {
            $method = 'DIGEST-MD5';
        }

        $this->_debug("C: Bind [mech: $method, authc: $authc, authz: $authz] [pass: $pass]");

        if (ldap_sasl_bind($this->conn, NULL, $pass, $method, NULL, $authc, $authz)) {
            $this->_debug("S: OK");
            return TRUE;
        }

        $this->_debug("S: ".ldap_error($this->conn));

        new PEAR_Error("Bind failed for authcid=$authc ".ldap_error($this->conn), ldap_errno($this->conn));
        return FALSE;
    }

    public function search($base_dn, $filter = '(objectclass=*)', $scope = 'sub', $sort = NULL, $search = Array())
    {
        if (!$this->conn) {
            new PEAR_Error("No active connection for " . __CLASS__ . "->" . __FUNCTION__);
            return FALSE;
        }

        $this->_debug("C: Search base dn: [$base_dn] scope [$scope] with filter [$filter]");

        if (empty($sort)) {
            $sort = $this->find_vlv($base_dn, $filter, $scope);
        } else {
            $sort = $this->find_vlv($base_dn, $filter, $scope, $sort);
        }

        if (!($sort === FALSE)) {
            $vlv_search = $this->_vlv_search($sort, $search);
            $this->vlv_active = $this->_vlv_set_controls($base_dn, $filter, $scope, $sort, $this->list_page, $this->page_size, $vlv_search);
        }

        $function = self::scope_to_function($scope, $ns_function);

        $this->_debug("Using function $function on scope $scope (\$ns_function is $ns_function)");

        if ($this->vlv_active && isset($this->additional_filter)) {
            $filter = "(&" . $filter . $this->additional_filter . ")";
            $this->_debug("C: Setting a filter of " . $filter);
        } else {
            $filter = "(&" . $filter . $this->additional_filter . ")";
            $this->_debug("C: (Without VLV) Setting a filter of " . $filter);
        }

        $this->_debug("Executing search with return attributes: " . var_export($this->return_attributes, TRUE));

        $ldap_result = @$function(
                $this->conn,
                $base_dn,
                $filter,
                $this->return_attributes,
                0,
                (int)$this->config['sizelimit'],
                (int)$this->config['timelimit']
            );

        if (!$ldap_result) {
            new PEAR_Error("$function failed for dn=$bind_dn: ".ldap_error($this->conn), ldap_errno($this->conn));
            return FALSE;
        }

        if ($this->vlv_active && function_exists('ldap_parse_virtuallist_control')) {
            if (ldap_parse_result($this->conn, $ldap_result, $errcode, $matcheddn, $errmsg, $referrals, $serverctrls)) {
                ldap_parse_virtuallist_control($this->conn, $serverctrls, $last_offset, $vlv_count, $vresult);
                $this->result = new Net_LDAP3_Result($this->conn, $base_dn, $filter, $scope, $ldap_result);
                $this->result->set('offset', $last_offset);
                $this->result->set('count', $vlv_count);
                $this->result->set('vlv', TRUE);
            } else {
                $this->_debug("S: " . ($errmsg ? $errmsg : ldap_error($this->conn)));
                new PEAR_Error("Something went terribly wrong");
            }
        } else {
            $this->result = new Net_LDAP3_Result($this->conn, $base_dn, $filter, $scope, $ldap_result);
        }

        return $this->result;
    }

    public function search_entries($base_dn, $filter = '(objectclass=*)', $scope = 'sub', $sort = NULL, $search = Array())
    {
        /*
            Use a search array with multiple keys and values that to continue
            to use the VLV but with an original filter adding the search stuff
            to an additional filter.
        */

        $this->_debug("Net_LDAP3::search_entries with search " . var_export($search, TRUE));

        if (is_array($search) && array_key_exists('params', $search)) {
            $this->_debug("C: Composing search filter");
            $_search = $this->search_filter($search);
            $this->_debug("C: Search filter: $_search");

            if (!empty($_search)) {
                $this->additional_filter = $_search;
            } else {
                $this->additional_filter = "(|";

                foreach ($search as $attr => $value) {
                    $this->additional_filter .= "(" . $attr . "=" . $this->_fuzzy_search_prefix() . $value . $this->_fuzzy_search_suffix() . ")";
                }

                $this->additional_filter .= ")";
            }

            $this->_debug("C: Setting an additional filter " . $this->additional_filter);
        }

        $search = $this->search($base_dn, $filter, $scope, $sort, $search);

        if (!$search) {
            $this->_debug("Net_LDAP3: Search did not succeed!");
            return FALSE;
        }

        return $this->result;

    }

    /**
     * Create LDAP search filter string according to defined parameters.
     */
    public function search_filter($search)
    {
        if (empty($search) || !is_array($search) || empty($search['params'])) {
            return NULL;
        }

        $filter = '';
        foreach ((array) $search['params'] as $field => $param) {
            switch ((string)$param['type']) {
                case 'prefix':
                    $prefix = '';
                    $suffix = '*';
                    break;
                case 'suffix':
                    $prefix = '*';
                    $suffix = '';
                    break;
                case 'exact':
                    $prefix = '';
                    $suffix = '';
                    break;
                case 'both':
                default:
                    $prefix = '*';
                    $suffix = '*';
                    break;
            }

            if (is_array($param['value'])) {
                $val_filter = array();
                foreach ($param['value'] as $val) {
                    $value = self::_quote_string($val);
                    $val_filter[] = "($field=$prefix" . $value . "$suffix)";
                }
                $filter .= "(|" . implode($val_filter, '') . ")";
            }
            else {
                $value = self::_quote_string($param['value']);
                $filter .= "($field=$prefix" . $value . "$suffix)";
            }
        }

        // join search parameters with specified operator ('OR' or 'AND')
        if (count($search['params']) > 1) {
            $filter = '(' . ($search['operator'] == 'AND' ? '&' : '|') . $filter . ')';
        }

        return $filter;
    }

    /**
     * Escapes a DN value according to RFC 2253
     *
     * @param string $dn DN value o quote
     * @return string The escaped value
     */
    public static function escape_dn($dn)
    {
        return strtr($str, Array(','=>'\2c', '='=>'\3d', '+'=>'\2b',
            '<'=>'\3c', '>'=>'\3e', ';'=>'\3b', '\\'=>'\5c',
            '"'=>'\22', '#'=>'\23'));
    }

    /**
     * Escapes the given value according to RFC 2254 so that it can be safely used in LDAP filters.
     *
     * @param string $val Value to quote
     * @return string The escaped value
     */
    public static function escape_value($val)
    {
        return strtr($str, Array('*'=>'\2a', '('=>'\28', ')'=>'\29',
            '\\'=>'\5c', '/'=>'\2f'));
    }

    /**
     * Turn an LDAP entry into a regular PHP array with attributes as keys.
     *
     * @param array $entry Attributes array as retrieved from ldap_get_attributes() or ldap_get_entries()
     * @return array       Hash array with attributes as keys
     */
    public static function normalize_entry($entry)
    {
        $rec = Array();
        for ($i=0; $i < $entry['count']; $i++) {
            $attr = $entry[$i];
            for ($j=0; $j < $entry[$attr]['count']; $j++) {
                $rec[$attr][$j] = $entry[$attr][$j];
            }
        }

        return $rec;
    }

    public static function normalize_result($__result)
    {
        if (!is_array($__result)) {
            return Array();
        }

        $result  = Array();

        for ($x = 0; $x < $__result["count"]; $x++) {
            $dn = $__result[$x]['dn'];
            $result[$dn] = Array();
            for ($y = 0; $y < $__result[$x]["count"]; $y++) {
                $attr = $__result[$x][$y];
                if ($__result[$x][$attr]["count"] == 1) {
                    switch ($attr) {
                        case "objectclass":
                            $result[$dn][$attr] = Array(strtolower($__result[$x][$attr][0]));
                            break;
                        default:
                            $result[$dn][$attr] = $__result[$x][$attr][0];
                            break;
                    }
                }
                else {
                    $result[$dn][$attr] = Array();
                    for ($z = 0; $z < $__result[$x][$attr]["count"]; $z++) {
                        switch ($attr) {
                            case "objectclass":
                                $result[$dn][$attr][] = strtolower($__result[$x][$attr][$z]);
                                break;
                            default:
                                $result[$dn][$attr][] = $__result[$x][$attr][$z];
                                break;
                        }
                    }
                }
            }
        }

        return $result;
    }

    public static function scopeint2str($scope) {
        switch ($scope) {
            case 2:
                return 'sub';
                break;
            case 1:
                return 'one';
                break;
            case 0:
                return 'base';
                break;
            default:
                new PEAR_Error("Scope $scope is not a valid scope integer");
                break;
        }
    }

    /**
     * Choose the right PHP function according to scope property
     *
     * @param string $scope         The LDAP scope (sub|base|list)
     * @param string $ns_function   Function to be used for numSubOrdinates queries
     * @return string  PHP function to be used to query directory
     */
    public static function scope_to_function($scope, &$ns_function = NULL)
    {
        switch ($scope) {
            case 'sub':
                $function = $ns_function  = 'ldap_search';
                break;
            case 'base':
                $function = $ns_function = 'ldap_read';
                break;
            case 'one':
            case 'list':
            default:
                $function = 'ldap_list';
                $ns_function = 'ldap_read';
                break;
        }

        return $function;
    }

    private function config_set_config_get_hook($callback) {
        $this->_config_get_hook = $callback;
    }

    private function config_set_config_set_hook($callback) {
        $this->_config_set_hook = $callback;
    }

    /**
     * Sets the debug level both for this class and the ldap connection.
     */
    private function config_set_debug($value) {
        if ($value === FALSE) {
            $this->config['debug'] = FALSE;
        } else {
            $this->config['debug'] = TRUE;
        }

        if ((int)($value) > 0) {
            ldap_set_option(NULL, LDAP_OPT_DEBUG_LEVEL, (int)($value));
        }
    }

    /**
     *  Sets a log hook that is called with every log message in this module.
     */
    private function config_set_log_hook($callback) {
        $this->_log_hook = $callback;
    }

    private function config_set_return_attributes($attribute_names = Array('entrydn')) {
        $this->_debug("setting return attributes: " . var_export($attribute_names, TRUE));
        $this->return_attributes = (Array)($attribute_names);
    }

    /**
     * Find a matching VLV
     */
    private function find_vlv($base_dn, $filter, $scope, $sort_attrs = NULL) {
        if (array_key_exists('vlv', $this->config) && $this->config['vlv'] === FALSE) {
            return FALSE;
        }

        if ($scope == 'base') {
            return FALSE;
        }

        if (empty($this->_vlv_indexes_and_searches)) {
            $this->_debug("No VLV information available yet, refreshing");
            $this->find_vlv_indexes_and_searches(TRUE);
        }

        if (empty($this->_vlv_indexes_and_searches) && !is_array($this->_vlv_indexes_and_searches)) {
            return FALSE;
        }

        $this->_debug("Existing vlv index and search information", $this->_vlv_indexes_and_searches);

        if (array_key_exists($base_dn, $this->_vlv_indexes_and_searches) && !empty($this->_vlv_indexes_and_searches[$base_dn])) {
            $this->_debug("Found a VLV for base_dn: " . $base_dn);
            if ($this->_vlv_indexes_and_searches[$base_dn]['filter'] == $filter) {
                $this->_debug("Filter matches");
                if ($this->_vlv_indexes_and_searches[$base_dn]['scope'] == $scope) {
                    $this->_debug("Scope matches");

                    // Not passing any sort attributes means you don't care
                    if (!empty($sort_attrs)) {
                        if (in_array($sort_attrs, $this->_vlv_indexes_and_searches[$base_dn]['sort'])) {
                            return $sort_attrs;
                        } else {
                            return FALSE;
                        }
                    } else {
                        return $this->_vlv_indexes_and_searches[$base_dn]['sort'][0];
                    }

                } else {
                    $this->_debug("Scope does not match. VLV: " . var_export($this->_vlv_indexes_and_searches[$base_dn]['scope'], TRUE) . " while looking for " . var_export($scope, TRUE));
                    return FALSE;
                }
            } else {
                $this->_debug("Filter does not match");
                return FALSE;
            }
        } else {
            $this->_debug("No VLV for base dn", $base_dn);
            return FALSE;
        }
    }

    /**
        Return VLV indexes and searches including necessary configuration
        details.
    */
    private function find_vlv_indexes_and_searches($refresh = FALSE) {
        if (!empty($this->config['vlv'])) {
            if ($this->config['vlv'] === FALSE) {
                return Array();
            } else {
                return $this->config['vlv'];
            }
        }

        if (!$this->_vlv_indexes_and_searches === NULL) {
            if (!$refresh) {
                return $this->_vlv_indexes_and_searches;
            }
        }

        $return_attributes = $this->return_attributes;

        $config_root_dn = $this->config_get('config_root_dn', NULL);
        if (empty($config_root_dn)) {
            return Array();
        }

        $this->return_attributes = Array('*');

        $search_result = ldap_search(
                $this->conn,
                $config_root_dn,
                '(objectclass=vlvsearch)',
                Array('*'),
                0,
                0,
                0
            );

        $vlv_searches = new Net_LDAP3_Result($this->conn, $config_root_dn, '(objectclass=vlvsearch)', 'sub', $search_result);

        if ($vlv_searches->count() < 1) {
            $this->_debug("Empty result from search for '(objectclass=vlvsearch)' on '$config_root_dn'");
            $this->return_attributes = $return_attributes;
            return;
        } else {
            $vlv_searches = $vlv_searches->entries(TRUE);
        }

        foreach ($vlv_searches as $vlv_search_dn => $vlv_search_attrs) {

            // The attributes we are interested in are as follows:
            $_vlv_base_dn = $vlv_search_attrs['vlvbase'];
            $_vlv_scope = $vlv_search_attrs['vlvscope'];
            $_vlv_filter = $vlv_search_attrs['vlvfilter'];

            // Multiple indexes may exist
            $index_result = ldap_search(
                    $this->conn,
                    $vlv_search_dn,
                    '(objectclass=vlvindex)',
                    Array('*'),
                    0,
                    0,
                    0
                );


            $vlv_indexes = new Net_LDAP3_Result($this->conn, $vlv_search_dn, '(objectclass=vlvindex)', 'sub', $index_result);
            $vlv_indexes = $vlv_indexes->entries(TRUE);

            $this->_debug("find_vlv() vlvindex result: " . var_export($vlv_indexes, TRUE));

            // Reset this one for each VLV search.
            $_vlv_sort = Array();

            foreach ($vlv_indexes as $vlv_index_dn => $vlv_index_attrs) {
                $_vlv_sort[] = explode(' ', $vlv_index_attrs['vlvsort']);
            }

            $this->_vlv_indexes_and_searches[$_vlv_base_dn] = Array(
                    'scope' => self::scopeint2str($_vlv_scope),
                    'filter' => $_vlv_filter,
                    'sort' => $_vlv_sort,
                );

        }

        $this->return_attributes = $return_attributes;

        $this->_debug("Refreshed VLV: " . var_export($this->_vlv_indexes_and_searches, TRUE));
    }

    private function init_schema()
    {
        $this->_ldap_uri    = $this->conf->get('ldap_uri');
        $this->_ldap_server = parse_url($this->_ldap_uri, PHP_URL_HOST);
        $this->_ldap_port   = parse_url($this->_ldap_uri, PHP_URL_PORT);
        $this->_ldap_scheme = parse_url($this->_ldap_uri, PHP_URL_SCHEME);

        require_once("Net/LDAP2.php");

        $_ldap_cfg = array(
            'host'   => $this->_ldap_server,
            'port'   => $this->_ldap_port,
            'tls'    => FALSE,
            'version' => 3,
            'binddn' => $this->conf->get('bind_dn'),
            'bindpw' => $this->conf->get('bind_pw')
        );

        $_ldap_schema_cache_cfg = array(
            'path' => "/tmp/" . $this->_ldap_server . ":" . ($this->_ldap_port ? $this->_ldap_port : '389') . "-Net_LDAP2_Schema.cache",
            'max_age' => 86400,
        );

        $_ldap_schema_cache = new Net_LDAP2_SimpleFileSchemaCache($_ldap_schema_cache_cfg);

        $_ldap = Net_LDAP2::connect($_ldap_cfg);

        $result = $_ldap->registerSchemaCache($_ldap_schema_cache);

        // TODO: We should learn what LDAP tech. we're running against.
        // Perhaps with a scope base objectclass recognize rootdse entry
        $schema_root_dn = $this->conf->get('schema_root_dn');
        if (!$schema_root_dn) {
            $_schema = $_ldap->schema();
        }

        return $_schema;
    }

    private function list_group_member($dn, $members, $recurse = TRUE)
    {
        $this->_debug("Called _list_group_member(" . $dn . ")");

        $group_members = array();

        $members = (array)($members);

        if (empty($members)) {
            return $group_members;
        }

        // Use the member attributes to return an array of member ldap objects
        // NOTE that the member attribute is supposed to contain a DN
        foreach ($members as $member) {
            $member_entry = $this->_read($member, '(objectclass=*)');

            if (empty($member_entry)) {
                continue;
            }

            $group_members[$member] = array_pop($member_entry);

            if ($recurse) {
                // Nested groups
                $group_group_members = $this->_list_group_members($member, $member_entry);
                if ($group_group_members) {
                    $group_members = array_merge($group_group_members, $group_members);
                }
            }
        }

        return array_filter($group_members);
    }

    private function list_group_uniquemember($dn, $uniquemembers, $recurse = TRUE)
    {
        $this->_debug("Called _list_group_uniquemember(" . $dn . ")", $entry);

        // Use the member attributes to return an array of member ldap objects
        // NOTE that the member attribute is supposed to contain a DN
        $group_members = array();
        if (empty($uniquemembers)) {
            return $group_members;
        }

        $uniquemembers = (array)($uniquemembers);

        if (is_string($uniquemembers)) {
            $this->_debug("uniquemember for entry is not an array");
            $uniquemembers = (array)($uniquemembers);
        }

        foreach ($uniquemembers as $member) {
            $member_entry = $this->_read($member, '(objectclass=*)');

            if (empty($member_entry)) {
                continue;
            }

            $group_members[$member] = array_pop($member_entry);

            if ($recurse) {
                // Nested groups
                $group_group_members = $this->_list_group_members($member, $member_entry);
                if ($group_group_members) {
                    $group_members = array_merge($group_group_members, $group_members);
                }
            }
        }

        return array_filter($group_members);
    }

    private function list_group_memberurl($dn, $memberurls, $recurse = TRUE)
    {
        $this->_debug("Called _list_group_memberurl(" . $dn . ")");

        // Use the member attributes to return an array of member ldap objects
        // NOTE that the member attribute is supposed to contain a DN

        $group_members = array();

        foreach ((array)($memberurls) as $url) {
            $ldap_uri_components = $this->_parse_memberurl($url);

            $entries = $this->search($ldap_uri_components[3], $ldap_uri_components[6]);

            foreach ($entries as $entry_dn => $_entry) {
                $group_members[$entry_dn] = $_entry;
                $this->_debug("Found " . $entry_dn);

                if ($recurse) {
                    // Nested group
                    $group_group_members = $this->_list_group_members($entry_dn, $_entry);
                    if ($group_group_members) {
                        $group_members = array_merge($group_members, $group_group_members);
                    }
                }
            }
        }

        return array_filter($group_members);
    }

    /**
     * memberUrl attribute parser
     *
     * @param string $url URL string
     *
     * @return array URL elements
     */
    private function parse_memberurl($url)
    {
        $this->_debug("Parsing URL: " . $url);
        preg_match('/(.*):\/\/(.*)\/(.*)\?(.*)\?(.*)\?(.*)/', $url, $matches);
        return $matches;
    }

    private function modify_entry_attributes($subject_dn, $attributes)
    {
        // Opportunities to set FALSE include failed ldap commands.
        $result = TRUE;

        if (is_array($attributes['rename']) && !empty($attributes['rename'])) {
            $olddn = $attributes['rename']['dn'];
            $newrdn = $attributes['rename']['new_rdn'];
            if (!empty($attributes['rename']['new_parent'])) {
                $new_parent = $attributes['rename']['new_parent'];
            } else {
                $new_parent = NULL;
            }

            $this->_debug("LDAP: C: Rename $olddn to $newrdn,$new_parent");

            $result = ldap_rename($this->conn, $olddn, $newrdn, $new_parent, TRUE);

            if ($result) {
                $this->_debug("LDAP: S: OK");

                if ($new_parent) {
                    $subject_dn = $newrdn . ',' . $new_parent;
                } else {
                    $old_parent_dn_components = ldap_explode_dn($olddn, 0);
                    unset($old_parent_dn_components["count"]);
                    $old_rdn = array_shift($old_parent_dn_components);
                    $old_parent_dn = implode(",", $old_parent_dn_components);
                    $subject_dn = $newrdn . ',' . $old_parent_dn;
                }
            }
            else {
                $this->_debug("LDAP: S: " . ldap_error($this->conn));
                Log::warning("LDAP: Failed to rename $olddn to $newrdn,$new_parent");
                return FALSE;
            }
        }

        if (is_array($attributes['replace']) && !empty($attributes['replace'])) {
            $this->_debug("LDAP: C: Mod-Replace $subject_dn: " . json_encode($attributes['replace']));

            $result = ldap_mod_replace($this->conn, $subject_dn, $attributes['replace']);

            if ($result) {
                $this->_debug("LDAP: S: OK");
            }
            else {
                $this->_debug("LDAP: S: " . ldap_error($this->conn));
                Log::warning("LDAP: Failed to replace attributes on $subject_dn: " . json_encode($attributes['replace']));
                return FALSE;
            }
        }

        if (is_array($attributes['del']) && !empty($attributes['del'])) {
            $this->_debug("LDAP: C: Mod-Delete $subject_dn: " . json_encode($attributes['del']));

            $result = ldap_mod_del($this->conn, $subject_dn, $attributes['del']);

            if ($result) {
                $this->_debug("LDAP: S: OK");
            }
            else {
                $this->_debug("LDAP: S: " . ldap_error($this->conn));
                Log::warning("LDAP: Failed to delete attributes on $subject_dn: " . json_encode($attributes['del']));
                return FALSE;
            }
        }


        if (is_array($attributes['add']) && !empty($attributes['add'])) {
            $this->_debug("LDAP: C: Mod-Add $subject_dn: " . json_encode($attributes['add']));

            $result = ldap_mod_add($this->conn, $subject_dn, $attributes['add']);

            if ($result) {
                $this->_debug("LDAP: S: OK");
            }
            else {
                $this->_debug("LDAP: S: " . ldap_error($this->conn));
                Log::warning("LDAP: Failed to add attributes on $subject_dn: " . json_encode($attributes['add']));
                return FALSE;
            }
        }

        return TRUE;
    }

    private function parse_attribute_level_rights($attribute_value)
    {
        $attribute_value  = str_replace(", ", ",", $attribute_value);
        $attribute_values = explode(",", $attribute_value);
        $attribute_value  = array();

        foreach ($attribute_values as $access_right) {
            $access_right_components = explode(":", $access_right);
            $access_attribute        = strtolower(array_shift($access_right_components));
            $access_value            = array_shift($access_right_components);

            $attribute_value[$access_attribute] = array();

            for ($i = 0; $i < strlen($access_value); $i++) {
                $method = $this->attribute_level_rights_map[substr($access_value, $i, 1)];

                if (!in_array($method, $attribute_value[$access_attribute])) {
                    $attribute_value[$access_attribute][] = $method;
                }
            }
        }

        return $attribute_value;
    }

    private function parse_entry_level_rights($attribute_value)
    {
        $_attribute_value = array();

        for ($i = 0; $i < strlen($attribute_value); $i++) {
            $method = $this->entry_level_rights_map[substr($attribute_value, $i, 1)];

            if (!in_array($method, $_attribute_value)) {
                $_attribute_value[] = $method;
            }
        }

        return $_attribute_value;
    }

    private function supported_controls()
    {
        $this->_info("Obtaining supported controls");
        $this->return_attributes = Array("supportedcontrol");
        $result = $this->search("", "(objectclass=*)", 'base');
        $result = $result->entries(TRUE);
        $this->_info("Obtained " . count($result['']['supportedcontrol']) . " supported controls");
        return $result['']['supportedcontrol'];
    }

    private function _alert() {
        $this->__log(LOG_ALERT, func_get_args());
    }

    private function _critical() {
        $this->__log(LOG_CRIT, func_get_args());
    }

    private function _debug() {
        $this->__log(LOG_DEBUG, func_get_args());
    }

    private function _emergency() {
        $this->__log(LOG_EMERG, func_get_args());
    }

    private function _error() {
        $this->__log(LOG_ERR, func_get_args());
    }

    private function _info() {
        $this->__log(LOG_INFO, func_get_args());
    }

    private function _notice() {
        $this->__log(LOG_NOTICE, func_get_args());
    }

    private function _warning() {
        $this->__log(LOG_WARNING, func_get_args());
    }

    private function _fuzzy_search_prefix() {
        switch ($this->config_get("fuzzy_search", 2)) {
            case 2:
                return "*";
                break;
            case 1:
            case 0:
            default:
                return "";
                break;
        }
    }

    private function _fuzzy_search_suffix() {
        switch ($this->config_get("fuzzy_search", 2)) {
            case 2:
                return "*";
                break;
            case 1:
                return "*";
            case 0:
            default:
                return "";
                break;
        }
    }

    private function _vlv_search($sort, $search) {
        if (!empty($this->additional_filter)) {
            $this->_debug("Not setting a VLV search filter because we already have a filter");
            return NULL;
        }

        $search_suffix = $this->_fuzzy_search_suffix();

        foreach ($search as $attr => $value) {
            if (!in_array(strtolower($attr), $sort)) {
                $this->_debug("Cannot use VLV search using attribute not indexed: $attr (not in " . var_export($sort, TRUE) . ")");
                return NULL;
            } else {
                return $value . $search_suffix;
            }
        }
    }

    /**
     * Set server controls for Virtual List View (paginated listing)
     */
    private function _vlv_set_controls($base_dn, $filter, $scope, $sort, $list_page, $page_size, $search = NULL)
    {
        $sort_ctrl = Array(
                'oid' => "1.2.840.113556.1.4.473",
                'value' => self::_sort_ber_encode($sort)
            );

        if (!empty($search)) {
            $this->_debug("_vlv_set_controls to include search: " . var_export($search, TRUE));
        }

        $vlv_ctrl  = Array(
                'oid' => "2.16.840.1.113730.3.4.9",
                'value' => self::_vlv_ber_encode(
                        ($offset = ($list_page-1) * $page_size + 1),
                        $page_size,
                        $search
                    ),
                'iscritical' => TRUE
            );

        $this->_debug("C: set controls sort=" . join(' ', unpack('H'.(strlen($sort_ctrl['value'])*2), $sort_ctrl['value'])) . " ($sort[0]);"
            . " vlv=" . join(' ', (unpack('H'.(strlen($vlv_ctrl['value'])*2), $vlv_ctrl['value']))) . " ($offset/$page_size)");

        if (!ldap_set_option($this->conn, LDAP_OPT_SERVER_CONTROLS, Array($sort_ctrl, $vlv_ctrl))) {
            $this->_debug("S: ".ldap_error($this->conn));
            $this->set_error(self::ERROR_SEARCH, 'vlvnotsupported');

            return FALSE;
        }

        return TRUE;
    }

    /**
     *  Log a message.
     */
    private function __log($level, $args)
    {
        $msg = Array();

        foreach ($args as $arg) {
            $msg[] = !is_string($arg) ? var_export($arg, true) : $arg;
        }

        if (!empty($this->_log_hook)) {
            call_user_func_array($this->_log_hook, Array($level, $msg));
            return;
        }

        if ($this->debug_level > 0) {
            syslog($level, implode("\n", $msg));
        }
    }

    /**
     *  Given a base dn, filter and scope, checks if the current result in
     *  $this->result is actually current.
     *
     *  @param  string  $base_dn    Base DN
     *  @param  string  $filter     Filter
     *  @param  string  $scope      Scope
     */
    private function __result_current($base_dn, $filter, $scope) {
        if (empty($this->result)) {
            return FALSE;
        }

        if ($this->result->get('base_dn') !== $base_dn) {
            return FALSE;
        }

        if ($this->result->get('filter') !== $filter) {
            return FALSE;
        }

        if ($this->result->get('scope') !== $scope) {
            return FALSE;
        }

        return TRUE;
    }

    /**
     * Returns unified attribute name (resolving aliases)
     */
    private static function _attr_name($namev)
    {
        // list of known attribute aliases
        static $aliases = Array(
            'gn' => 'givenname',
            'rfc822mailbox' => 'email',
            'userid' => 'uid',
            'emailaddress' => 'email',
            'pkcs9email' => 'email',
        );

        list($name, $limit) = explode(':', $namev, 2);
        $suffix = $limit ? ':'.$limit : '';

        return (isset($aliases[$name]) ? $aliases[$name] : $name) . $suffix;
    }

    /**
     * Add BER sequence with correct length and the given identifier
     */
    private static function _ber_addseq($str, $identifier)
    {
        $len = dechex(strlen($str)/2);
        if (strlen($len) % 2 != 0)
            $len = '0'.$len;

        return $identifier . $len . $str;
    }

    /**
     * Returns BER encoded integer value in hex format
     */
    private static function _ber_encode_int($offset)
    {
        $val = dechex($offset);
        $prefix = '';

        // check if bit 8 of high byte is 1
        if (preg_match('/^[89abcdef]/', $val))
            $prefix = '00';

        if (strlen($val)%2 != 0)
            $prefix .= '0';

        return $prefix . $val;
    }

    /**
     * Quotes attribute value string
     *
     * @param string $str Attribute value
     * @param bool   $dn  True if the attribute is a DN
     *
     * @return string Quoted string
     */
    private static function _quote_string($str, $is_dn = FALSE)
    {
        // take firt entry if array given
        if (is_array($str)) {
            $str = reset($str);
        }

        if ($is_dn) {
            $replace = array(
                    ',' => '\2c',
                    '=' => '\3d',
                    '+' => '\2b',
                    '<' => '\3c',
                    '>' => '\3e',
                    ';' => '\3b',
                    "\\"=> '\5c',
                    '"' => '\22',
                    '#' => '\23'
                );
        } else {
            $replace = array(
                    '*' => '\2a',
                    '(' => '\28',
                    ')' => '\29',
                    "\\" => '\5c',
                    '/' => '\2f'
                );
        }

        return strtr($str, $replace);
    }

    /**
     * create ber encoding for sort control
     *
     * @param array List of cols to sort by
     * @return string BER encoded option value
     */
    private static function _sort_ber_encode($sortcols)
    {
        $str = '';
        foreach (array_reverse((array)$sortcols) as $col) {
            $ber_val = self::_string2hex($col);

            # 30 = ber sequence with a length of octet value
            # 04 = octet string with a length of the ascii value
            $oct = self::_ber_addseq($ber_val, '04');
            $str = self::_ber_addseq($oct, '30') . $str;
        }

        // now tack on sequence identifier and length
        $str = self::_ber_addseq($str, '30');

        return pack('H'.strlen($str), $str);
    }

    /**
     * Returns ascii string encoded in hex
     */
    private static function _string2hex($str)
    {
        $hex = '';
        for ($i=0; $i < strlen($str); $i++)
            $hex .= dechex(ord($str[$i]));
        return $hex;
    }

    /**
     * Generate BER encoded string for Virtual List View option
     *
     * @param integer List offset (first record)
     * @param integer Records per page
     * @return string BER encoded option value
     */
    private static function _vlv_ber_encode($offset, $rpp, $search = '')
    {
        # this string is ber-encoded, php will prefix this value with:
        # 04 (octet string) and 10 (length of 16 bytes)
        # the code behind this string is broken down as follows:
        # 30 = ber sequence with a length of 0e (14) bytes following
        # 02 = type integer (in two's complement form) with 2 bytes following (beforeCount): 01 00 (ie 0)
        # 02 = type integer (in two's complement form) with 2 bytes following (afterCount):  01 18 (ie 25-1=24)
        # a0 = type context-specific/constructed with a length of 06 (6) bytes following
        # 02 = type integer with 2 bytes following (offset): 01 01 (ie 1)
        # 02 = type integer with 2 bytes following (contentCount):  01 00

        # whith a search string present:
        # 81 = type context-specific/constructed with a length of 04 (4) bytes following (the length will change here)
        # 81 indicates a user string is present where as a a0 indicates just a offset search
        # 81 = type context-specific/constructed with a length of 06 (6) bytes following

        # the following info was taken from the ISO/IEC 8825-1:2003 x.690 standard re: the
        # encoding of integer values (note: these values are in
        # two-complement form so since offset will never be negative bit 8 of the
        # leftmost octet should never by set to 1):
        # 8.3.2: If the contents octets of an integer value encoding consist
        # of more than one octet, then the bits of the first octet (rightmost) and bit 8
        # of the second (to the left of first octet) octet:
        # a) shall not all be ones; and
        # b) shall not all be zero

        if ($search)
        {
            $search = preg_replace('/[^-[:alpha:] ,.()0-9]+/', '', $search);
            $ber_val = self::_string2hex($search);
            $str = self::_ber_addseq($ber_val, '81');
        }
        else
        {
            # construct the string from right to left
            $str = "020100"; # contentCount

            $ber_val = self::_ber_encode_int($offset);  // returns encoded integer value in hex format

            // calculate octet length of $ber_val
            $str = self::_ber_addseq($ber_val, '02') . $str;

            // now compute length over $str
            $str = self::_ber_addseq($str, 'a0');
        }

        // now tack on records per page
        $str = "020100" . self::_ber_addseq(self::_ber_encode_int($rpp-1), '02') . $str;

        // now tack on sequence identifier and length
        $str = self::_ber_addseq($str, '30');

        return pack('H'.strlen($str), $str);
    }

}
?>
