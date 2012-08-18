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

    public $conn;
    public $vlv_active = FALSE;

    protected $config = Array(
            'sizelimit' => 0,
            'timelimit' => 0
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
        if (!empty($config) && is_array($config)) {
            foreach ($config as $key => $value) {
                if (!isset($this->config[$key]) || empty($this->config[$key])) {
                    $this->config[$key] = $value;
                }
            }
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
            return call_user_func($this->_config_get_hook, Array($key, $value));
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
            $this->$key = $value;
        } else {
            $this->config[$key] = $value;
        }
    }

    /**
     *  Establish a connection to the LDAP server
     */
    public function connect()
    {
        if (!function_exists('ldap_connect')) {
            PEAR::raiseError("No ldap support in this PHP installation", 100);
            return FALSE;
        }

        if (is_resource($this->conn)) {
            $this->debug("Connection already exists");
            return TRUE;
        }

        $config_hosts = $this->config_get('hosts', Array());
        $config_host = $this->config_get('host', NULL);

        if (empty($config_hosts)) {
            if (empty($config_host)) {
                PEAR::raiseError("No host or hosts configured", __LINE__);
                return FALSE;
            }

            $this->config_set('hosts', Array($this->config_get('host')));
        }

        var_dump($this->config);

        $port = $this->config_get('port', 389);

        foreach ($this->config_get('hosts') as $host) {
            $this->debug("C: Connect [$host:$port]");

            if ($lc = @ldap_connect($host, $port))
            {
                if ($this->config_get('use_tls', FALSE) === TRUE) {
                    if (!ldap_start_tls($lc)) {
                        $this->debug("S: Could not start TLS.");
                        continue;
                    }
                }

                $this->debug("S: OK");

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

            $this->debug("S: NOT OK");
        }

        if (!is_resource($this->conn)) {
            PEAR::raiseError("Could not connect to LDAP", 100);
            return FALSE;
        }

        return TRUE;
    }

    /**
     * Find a matching VLV
     */
    public function find_vlv_for($base_dn, $filter, $scope, $sort_attrs = NULL) {
        if (!empty($this->config['vlv']) && $this->config['vlv'] === FALSE) {
            return FALSE;
        }

        if ($this->_vlv_indexes_and_searches === NULL) {
            $this->find_vlv_indexes_and_searches();
        }

        $this->debug("Attempting to find VLV");

        if (!empty($this->_vlv_indexes_and_searches[$base_dn])) {
            $this->debug("Found a VLV for base_dn: " . $base_dn);
            if ($this->_vlv_indexes_and_searches[$base_dn]['filter'] == $filter) {
                $this->debug("Filter matches");
                if ($this->_vlv_indexes_and_searches[$base_dn]['scope'] == $scope) {
                    $this->debug("Scope matches");

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
                    $this->debug("Scope does not match. VLV: " . var_export($this->_vlv_indexes_and_searches[$base_dn]['scope'], TRUE) . " while looking for " . var_export($scope, TRUE));
                    return FALSE;
                }
            } else {
                $this->debug("Filter does not match");
                return FALSE;
            }
        } else {
            $this->debug("No VLV for base dn: " . $base_dn);
            return FALSE;
        }
    }

    /**
        Return VLV indexes and searches including necessary configuration
        details.
    */
    public function find_vlv_indexes_and_searches($refresh = FALSE) {
        if (!empty($this->config['vlv']) && $this->config['vlv'] === FALSE) {
            return Array();
        }

        if (!$this->_vlv_indexes_and_searches === NULL) {
            if (!$refresh) {
                return $this->_vlv_indexes_and_searches;
            }
        }

        $this->_vlv_indexes_and_searches = Array();

        $return_attributes = $this->return_attributes;

        $this->return_attributes = Array('*');

        $config_root_dn = $this->config_get('config_root_dn', NULL);
        if (empty($config_root_dn)) {
            return Array();
        }

        $vlv_searches = $this->__search(
                $config_root_dn,
                '(objectclass=vlvsearch)'
            );

        $vlv_searches = $this->result->entries(TRUE);

        $this->debug("find_vlv() results: " . var_export($vlv_searches, TRUE));

        foreach ($vlv_searches as $vlv_search_dn => $vlv_search_attrs) {

            // The attributes we are interested in are as follows:
            $_vlv_base_dn = $vlv_search_attrs['vlvbase'];
            $_vlv_scope = $vlv_search_attrs['vlvscope'];
            $_vlv_filter = $vlv_search_attrs['vlvfilter'];

            // Multiple indexes may exist
            $vlv_indexes = $this->__search(
                    $vlv_search_dn,
                    '(objectclass=vlvindex)'
                );

            $vlv_indexes = $this->result->entries(TRUE);

            $this->debug("find_vlv() vlvindex result: " . var_export($vlv_indexes, TRUE));

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

        $this->debug("Refreshed VLV: " . var_export($this->_vlv_indexes_and_searches, TRUE));
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
            PEAR::raiseError("Unable to bind: ldap_sasl_bind() not exists", 100);
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

        $this->debug("C: Bind [mech: $method, authc: $authc, authz: $authz] [pass: $pass]");

        if (ldap_sasl_bind($this->conn, NULL, $pass, $method, NULL, $authc, $authz)) {
            $this->debug("S: OK");
            return TRUE;
        }

        $this->debug("S: ".ldap_error($this->conn));

        PEAR::raiseError("Bind failed for authcid=$authc ".ldap_error($this->conn), ldap_errno($this->conn));
        return FALSE;
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

        $this->debug("C: Bind [dn: $bind_dn] [pass: $bind_pw]");

        if (@ldap_bind($this->conn, $bind_dn, $bind_pw)) {
            $this->debug("S: OK");
            $this->_current_bind_dn = $bind_dn;
            return TRUE;
        }

        $this->debug("S: ".ldap_error($this->conn));

        PEAR::raiseError("Bind failed for dn=$bind_dn: ".ldap_error($this->conn), ldap_errno($this->conn));
        return FALSE;
    }

    public function login($username, $password) {
        $_bind_dn = $this->config_get('service_bind_dn');
        $_bind_pw = $this->config_get('service_bind_pw');

        if (empty($_bind_dn)) {
            PEAR::raiseError("No valid service bind dn found.");
            return NULL;
        }

        if (empty($_bind_pw)) {
            PEAR::raiseError("No valid service bind password found.");
            return NULL;
        }

        $bound = $this->bind($_bind_dn, $_bind_pw);

        if (!$bound) {
            PEAR::raiseError("Could not bind with service bind credentials.");
            return NULL;
        }

        $base_dn = $this->config_get('root_dn');

        if (empty($base_dn)) {
            PEAR::raiseError("Could not get a valid base dn to search.");
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

        $filter = "(&(|(mail=%s)(alias=%s)(uid=%s))(objectclass=inetorgperson))";

        $replace_patterns = Array(
                '/%s/' => $username,
                '/%d/' => $domain,
                '/%U/' => $localpart,
                '/%r/' => $realm
            );

        $filter = preg_replace(array_keys($replace_patterns), array_values($replace_patterns), $filter);

        var_dump($filter);

        $result = $this->search($base_dn, $filter, 'sub');

        if ($result->count() > 1) {
            PEAR::raiseError("Multiple entries found.");
            return NULL;
        } else if ($result->count() < 1) {
            PEAR::raiseError("No entries found.");
            return NULL;
        }

        $entries = $this->result->entries();
        $entry = self::normalize_result($entries);
        $entry_dn = key($entry);

        $bound = $this->bind($entry_dn, $password);

        if (!$bound) {
            PEAR::raiseError("Count not bind with " . $entry_dn);
            return NULL;
        }

        return $entry_dn;
    }

    /**
     * Close connection to LDAP server
     */
    public function close()
    {
        if ($this->conn) {
            $this->debug("C: Close");
            ldap_unbind($this->conn);
            $this->conn = NULL;
        }
    }


    /**
     * Return the last result set
     *
     * @return object rcube_ldap_result Result object
     */
    function get_result()
    {
        return $this->result;
    }


    /**
     * Get a specific LDAP entry, identified by its DN
     *
     * @param string $dn Record identifier
     * @return array     Hash array
     */
    function get_entry($dn)
    {
        $rec = NULL;

        if ($this->conn && $dn) {
            $this->debug("C: Read [dn: $dn] [(objectclass=*)]");

            if ($ldap_result = @ldap_read($this->conn, $dn, '(objectclass=*)', $this->return_attributes)) {
//                $this->debug("S: OK");

                if ($entry = ldap_first_entry($this->conn, $ldap_result)) {
                    $rec = ldap_get_attributes($this->conn, $entry);
                }
            }
            else {
                $this->debug("S: ".ldap_error($this->conn));
            }

            if (!empty($rec)) {
                $rec['dn'] = $dn; // Add in the dn for the entry.
            }
        }

        return $rec;
    }

    /*
        Get the total number of entries.
    */
    public function get_count($base_dn, $filter = '(objectclass=*)', $scope = 'sub')
    {
        if (!$this->__result_current($base_dn, $filter, $scope)) {
            PEAR::raiseError("No current search result for these search parameters");
            return FALSE;
        }

        return $this->result->get_total();
    }

    public function list_entries($base_dn, $filter = '(objectclass=*)', $scope = 'sub', $sort = NULL)
    {
        $search = $this->__search($base_dn, $filter, $scope, $sort);

        if (!$search) {
            $this->debug("Net_LDAP3: Search did not succeed!");
            return FALSE;
        }

        $result = Array(
                'entries' => $this->result->entries(TRUE),
                'offset' => $this->result->get('offset'),
                'total' => $this->result->get('total'),
                'vlv' => $this->result->get('vlv', FALSE)
            );

        return $result;

    }

    public function search_entries($base_dn, $filter = '(objectclass=*)', $scope = 'sub', $sort = NULL, $search = Array())
    {
        /*
            Use a search array with multiple keys and values that to continue
            to use the VLV but with an original filter adding the search stuff
            to an additional filter.
        */

        if (count($search) > 1) {
            $_search = $this->_search_filter($search);

            if (!empty($_search)) {
                $this->additional_filter = $_search;
            } else {
                $this->additional_filter = "(|";

                foreach ($search as $attr => $value) {
                    $this->additional_filter .= "(" . $attr . "=" . $this->_fuzzy_search_prefix() . $value . $this->_fuzzy_search_suffix() . ")";
                }

                $this->additional_filter .= ")";
            }

            $this->debug("C: Setting an additional filter " . $this->additional_filter);
        }

        $search = $this->__search($base_dn, $filter, $scope, $sort, $search);

        if (!$search) {
            $this->debug("Net_LDAP3: Search did not succeed!");
            return FALSE;
        }

        $result = Array(
                'entries' => $this->result->entries(TRUE),
                'offset' => $this->result->get('offset'),
                'total' => $this->result->get('total'),
                'vlv' => $this->result->get('vlv', FALSE)
            );

        return $result;

    }

    public function __search($base_dn, $filter = '(objectclass=*)', $scope = 'sub', $sort = NULL, $search = Array())
    {
        if (!$this->conn) {
            PEAR::raiseError("No active connection for " . __CLASS__ . "->" . __FUNCTION__);
            return FALSE;
        }

/* TODO
        if (!$this->bind_status) {
            PEAR::raiseError("Inappropriate authorization: Not bound in " . __CLASS__ . "->" . __FUNCTION__);
            return FALSE;
        }
*/
        $this->debug("C: Search base dn: [$base_dn] scope [$scope] with filter [$filter]");

        if (empty($sort)) {
            $sort = $this->find_vlv_for($base_dn, $filter, $scope);
        } else {
            $sort = $this->find_vlv_for($base_dn, $filter, $scope, $sort);
        }

        if (!($sort === FALSE)) {
            $vlv_search = $this->_vlv_search($sort, $search);
            $this->vlv_active = $this->_vlv_set_controls($base_dn, $filter, $scope, $sort, $this->list_page, $this->page_size, $vlv_search);
        }

        $function = self::scope_to_function($scope, $ns_function);

        if (isset($this->additional_filter)) {
            $filter = "(&" . $filter . $this->additional_filter . ")";
            $this->debug("C: Setting a filter of " . $filter);
        }

        $ldap_result = $function(
                $this->conn,
                $base_dn,
                $filter,
                $this->return_attributes,
                0,
                (int)$this->config['sizelimit'],
                (int)$this->config['timelimit']
            );

        if ($this->vlv_active && function_exists('ldap_parse_virtuallist_control')) {
            if (ldap_parse_result($this->conn, $ldap_result, $errcode, $matcheddn, $errmsg, $referrals, $serverctrls)) {
                ldap_parse_virtuallist_control($this->conn, $serverctrls, $last_offset, $vlv_count, $vresult);
                $this->result = new Net_LDAP3_Result($this->conn, $base_dn, $filter, $scope, $ldap_result);
                $this->result->set('offset', $last_offset);
                $this->result->set('total', $vlv_count);
                $this->result->set('vlv', TRUE);
            } else {
                $this->debug("S: ".($errmsg ? $errmsg : ldap_error($this->conn)));
                PEAR::raiseError("Something went terribly wrong");
            }
        } else {
            $this->result = new Net_LDAP3_Result($this->conn, $base_dn, $filter, $scope, $ldap_result);
        }

        return TRUE;
    }

    /**
     * Modify an LDAP entry on the server
     *
     * @param string $dn      Entry DN
     * @param array  $params  Hash array of entry attributes
     * @param int    $mode    Update mode (UPDATE_MOD_ADD | UPDATE_MOD_DELETE | UPDATE_MOD_REPLACE)
     */
    public function modify($dn, $parms, $mode = 255)
    {
        // TODO: implement this

        return FALSE;
    }

    /**
     * Wrapper for ldap_add()
     *
     * @see ldap_add()
     */
    public function add($dn, $entry)
    {
        $this->debug("C: Add [dn: $dn]: ".print_r($entry, TRUE));

        $res = ldap_add($this->conn, $dn, $entry);
        if ($res === FALSE) {
            $this->debug("S: ".ldap_error($this->conn));
            return FALSE;
        }

//        $this->debug("S: OK");
        return TRUE;
    }

    /**
     * Wrapper for ldap_delete()
     *
     * @see ldap_delete()
     */
    public function delete($dn)
    {
        $this->debug("C: Delete [dn: $dn]");

        $res = ldap_delete($this->conn, $dn);
        if ($res === FALSE) {
            $this->debug("S: ".ldap_error($this->conn));
            return FALSE;
        }

//        $this->debug("S: OK");
        return TRUE;
    }

    /**
     * Wrapper for ldap_mod_replace()
     *
     * @see ldap_mod_replace()
     */
    public function mod_replace($dn, $entry)
    {
        $this->debug("C: Replace [dn: $dn]: ".print_r($entry, TRUE));

        if (!ldap_mod_replace($this->conn, $dn, $entry)) {
            $this->debug("S: ".ldap_error($this->conn));
            return FALSE;
        }

        $this->debug("S: OK");
        return TRUE;
    }

    /**
     * Wrapper for ldap_mod_add()
     *
     * @see ldap_mod_add()
     */
    public function mod_add($dn, $entry)
    {
        $this->debug("C: Add [dn: $dn]: ".print_r($entry, TRUE));

        if (!ldap_mod_add($this->conn, $dn, $entry)) {
            $this->debug("S: ".ldap_error($this->conn));
            return FALSE;
        }

        $this->debug("S: OK");
        return TRUE;
    }

    /**
     * Wrapper for ldap_mod_del()
     *
     * @see ldap_mod_del()
     */
    public function mod_del($dn, $entry)
    {
        $this->debug("C: Delete [dn: $dn]: ".print_r($entry, TRUE));

        if (!ldap_mod_del($this->conn, $dn, $entry)) {
            $this->debug("S: ".ldap_error($this->conn));
            return FALSE;
        }

        $this->debug("S: OK");
        return TRUE;
    }

    /**
     * Wrapper for ldap_rename()
     *
     * @see ldap_rename()
     */
    public function rename($dn, $newrdn, $newparent = NULL, $deleteoldrdn = TRUE)
    {
        $this->debug("C: Rename [dn: $dn] [dn: $newrdn]");

        if (!ldap_rename($this->conn, $dn, $newrdn, $newparent, $deleteoldrdn)) {
            $this->debug("S: ".ldap_error($this->conn));
            return FALSE;
        }

        $this->debug("S: OK");
        return TRUE;
    }

    /**
     * Wrapper for ldap_read() + ldap_get_entries()
     *
     * @see ldap_read()
     * @see ldap_get_entries()
     */
    public function read_entries($dn, $filter, $return_attributes = NULL)
    {
        $this->debug("C: Read [dn: $dn] [{$filter}]");

        if ($this->conn) {
            if (!$return_attributes)
                $return_attributes = $this->return_attributes;

            $result = ldap_read($dn, $filter, $return_attributes, 0, (int)$this->config['sizelimit'], (int)$this->config['timelimit']);
            if ($result === FALSE) {
                $this->debug("S: ".ldap_error($this->conn));
                return FALSE;
            }

//            $this->debug("S: OK");
            return ldap_get_entries($this->conn, $result);
        }

        return FALSE;
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
                PEAR::raiseError("Scope $scope is not a valid scope integer");
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

    /**
     * Create LDAP search filter string according to defined parameters.
     */
    private function _search_filter($search)
    {
        if (empty($search) || !is_array($search) || empty($search['params'])) {
            return null;
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

    private function _vlv_search($sort, $search) {
        if (!empty($this->additional_filter)) {
            $this->debug("Not setting a VLV search filter because we already have a filter");
            return NULL;
        }

        $search_suffix = $this->_fuzzy_search_suffix();

        foreach ($search as $attr => $value) {
            if (!in_array(strtolower($attr), $sort)) {
                $this->debug("Cannot use VLV search using attribute not indexed: $attr (not in " . var_export($sort, true) . ")");
                return NULL;
            } else {
                return $value . $search_suffix;
            }
        }
    }

    public function effective_rights($subject) {

        /*
            Invalid syntax

        $null_padded_string = '';

        for ($i = 0; $i<strlen($subject); $i++) {
            $null_padded_string .= substr($subject,$i,1)."\0";
        }
        $ber_subject = base64_encode($null_padded_string);

        */

        /*
            Invalid syntax

        $ber_subject = self::_sort_ber_encode(array($subject));

        */

        $er_ctrl = Array(
                'oid' => "1.3.6.1.4.1.42.2.27.9.5.2",
                'value' => $ber_subject,
                'iscritical' => TRUE
            );

        if (!ldap_set_option($this->conn, LDAP_OPT_SERVER_CONTROLS, Array($er_ctrl))) {
            $this->debug("S: " . ldap_error($this->conn));
        }

        return $this->__search($subject, '(objectclass=*)', 'base');
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
            $this->debug("_vlv_set_controls to include search: " . var_export($search, true));
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

        $this->debug("C: set controls sort=" . join(' ', unpack('H'.(strlen($sort_ctrl['value'])*2), $sort_ctrl['value'])) . " ($sort[0]);"
            . " vlv=" . join(' ', (unpack('H'.(strlen($vlv_ctrl['value'])*2), $vlv_ctrl['value']))) . " ($offset/$page_size)");

        if (!ldap_set_option($this->conn, LDAP_OPT_SERVER_CONTROLS, Array($sort_ctrl, $vlv_ctrl))) {
            $this->debug("S: ".ldap_error($this->conn));
            $this->set_error(self::ERROR_SEARCH, 'vlvnotsupported');

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
     * Prints debug info to the log
     */
    private function debug($str)
    {
        if (!empty($this->_log_hook)) {
            call_user_func_array($this->_log_hook, Array($str));
            return;
        }

        if ($this->debug_level > 0) {
            error_log("$str");
        }
    }


    /**
     * Quotes attribute value string
     *
     * @param string $str Attribute value
     * @param bool   $dn  True if the attribute is a DN
     *
     * @return string Quoted string
     */
    private static function _quote_string($str, $dn=FALSE)
    {
        // take firt entry if array given
        if (is_array($str))
            $str = reset($str);

        if ($dn)
            $replace = Array(','=>'\2c', '='=>'\3d', '+'=>'\2b', '<'=>'\3c',
                '>'=>'\3e', ';'=>'\3b', '\\'=>'\5c', '"'=>'\22', '#'=>'\23');
        else
            $replace = Array('*'=>'\2a', '('=>'\28', ')'=>'\29', '\\'=>'\5c',
                '/'=>'\2f');

        return strtr($str, $replace);
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
     * Returns ascii string encoded in hex
     */
    private static function _string2hex($str)
    {
        $hex = '';
        for ($i=0; $i < strlen($str); $i++)
            $hex .= dechex(ord($str[$i]));
        return $hex;
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
        print "Setting log_hook to $callback\n";
        $this->_log_hook = $callback;
    }

    private function config_set_return_attributes($attribute_names = Array('entrydn')) {
        $this->return_attributes = (Array)($attribute_names);
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

}
?>