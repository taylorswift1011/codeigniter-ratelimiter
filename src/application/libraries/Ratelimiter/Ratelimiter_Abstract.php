<?php

require_once('Ratelimiter_Interface.php');

abstract class Ratelimiter_Abstract implements Ratelimiter_Interface {

	protected $CI;
	protected $configurable;
	protected $sql;

	public function __construct(){
		$this->CI = &get_instance();
		$this->CI->config->load('ratelimiter');

		$this->configurable = array(
			'requests',
			'duration',
			'block_duration',
			'resource',
			'user_data',
			'whitelist_ips',
			'blacklist_ips',
			'response_type'
		);

		$configuration = $this->CI->config;
		if (
			!$configuration->item('ratelimit_table') ||
			$configuration->item('requests') === NULL ||
			!$configuration->item('duration') ||
			!$configuration->item('block_duration') ||
			!is_array($configuration->item('resource')) ||
			!is_array($configuration->item('user_data')) ||
			!$configuration->item('response_type') ||
			!$configuration->item('database_connection')
		) {
			throw new \Exception("Invalid Configuration");
		}

		$this->db = $this->CI->db;
		$this->table = $configuration->item('ratelimit_table');
		$this->history_backup = $configuration->item('history_backup');
		$this->history_table = $configuration->item('ratelimit_history_table');

		// Setting Configurable
		foreach ($this->configurable as $config)
			$this->{$config} = $configuration->item($config);
	}

	/**
	 *    Returns TRUE if already blocked
	 *
	 * @param array $data
	 * @return boolean
	 */
	protected function verify_if_already_blocked(array $data){
		$this->db
			->where([
				'blocked_till >=' => date('Y-m-d H:i:s'),
			]);

		$this->prepare_blocking_sqls($data);

		$result = $this->db
			->get()
			->first_row();

		if ($result && $result->blocked_till)
			return $result->blocked_till;

		return FALSE;
	}

	/**
	 *    Returns TRUE if request should be blocked.
	 *
	 * @param array $data
	 * @return boolean
	 */
	protected function verify_if_should_be_blocked(array $data){
		if ($this->requests == 0)
			return FALSE;

		$this->db
			->select('COUNT(*) AS count')
			->where('created_at >=', date('Y-m-d H:i:s', strtotime("- {$this->duration} minutes")));

		$this->prepare_blocking_sqls($data);

		$result = $this->db
			->get()
			->first_row();

		return (int)$result->count >= $this->requests;
	}

	/**
	 *    Logs current request into the database.
	 *    Return TRUE if logged successfully, else FALSE.
	 *
	 * @param array $data
	 * @param boolean $should_be_blocked
	 * @return boolean
	 */
	protected function log_request(array $data, bool $should_be_blocked){
		if ($should_be_blocked)
			$blocked_till = date('Y-m-d H:i:s', strtotime("+ {$this->block_duration} minutes"));

		$db_update = array(
			'request_url' => $_SERVER['REQUEST_URI'],
			'ip_address' => $this->get_client_ip(),
			'blocked_till' => isset($blocked_till) ? $blocked_till : NULL,
			'last_updated_at' => date('Y-m-d H:i:s'),
		);

		$data = array_intersect_key($data, array_merge($this->resource, $this->user_data));

		$response = new \stdClass();
		$response->success = $this->db
			->replace($this->table, array_merge($db_update, $data));

		$response->blocked_on_this_request = $should_be_blocked;
		$response->blocked_till = $should_be_blocked ? $blocked_till : NULL;

		return $response;
	}

	/**
	 *    Build SQLs for verify_if_already_blocked() and verify_if_should_be_blocked() functions.
	 *
	 * @param string $sql
	 * @param array $sql_data
	 * @param array $data
	 */
	protected function prepare_blocking_sqls(array $data){
		$data = array_intersect_key($data, ['class_name' => 1, 'method_name' => 1, 'ip_address' => 1]);

		$this->db
			->from($this->table)
			->where($data);

		$track_by_user_data = FALSE;
		foreach ($this->user_data as $key => $user_data)
			if ($user_data && isset($data[$key]))
				$track_by_user_data = TRUE;

		if (!$track_by_user_data)
			$this->db
				->where('ip_address', $this->get_client_ip());
	}

	/**
	 *    Returns client's IP address
	 *
	 * @return string
	 */
	protected function get_client_ip(){
		$ip_address = '';
		if (isset($_SERVER['HTTP_CLIENT_IP']))
			$ip_address = $_SERVER['HTTP_CLIENT_IP'];
		else if (isset($_SERVER['HTTP_X_FORWARDED_FOR']))
			$ip_address = $_SERVER['HTTP_X_FORWARDED_FOR'];
		else if (isset($_SERVER['HTTP_X_FORWARDED']))
			$ip_address = $_SERVER['HTTP_X_FORWARDED'];
		else if (isset($_SERVER['HTTP_FORWARDED_FOR']))
			$ip_address = $_SERVER['HTTP_FORWARDED_FOR'];
		else if (isset($_SERVER['HTTP_FORWARDED']))
			$ip_address = $_SERVER['HTTP_FORWARDED'];
		else if (isset($_SERVER['REMOTE_ADDR']))
			$ip_address = $_SERVER['REMOTE_ADDR'];
		else
			$ip_address = 'UNKNOWN';
		return $ip_address;
	}

	/**
	 *    Returns TRUE if client's IP address is in whitelisted IPs array
	 *
	 * @return boolean
	 */
	protected function ip_is_whitelisted(){
		return in_array($this->get_client_ip(), $this->whitelist_ips);
	}

	/**
	 *    Returns TRUE if client's IP address is in blacklisted IPs array
	 *
	 * @return boolean
	 */
	protected function ip_is_blacklisted(){
		return in_array($this->get_client_ip(), $this->blacklist_ips);
	}

	/**
	 *    Returns response from the library in desired format
	 *
	 * @param array
	 * @return mixed
	 */
	protected function send_response($data){
		switch (strtolower($this->response_type)) {
			case 'object':
				return (object)$data;
			case 'json':
				echo_json($data);
			case 'array':
			default:
				return $data;
		}
	}
}
