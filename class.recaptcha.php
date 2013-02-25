<?php
/**
 * Google reCatpcha API Base class
 *
 * @license BSD http://www.opensource.org/licenses/bsd-license.php
 */
abstract class reCaptchaBase {
    /**
     * public key for encryption
     *
     * @var string
     */
    protected $public_key;

    /**
     * protected key for encryption
     *
     * @var string
     */
    protected $protected_key;

    /**
     * curl resource instance
     *
     * @var resource
     */
    private $ch;

    /**
     * Google reCaptcha API URL
     *
     * @var string
     */
    static protected $api_server = 'www.google.com/recaptcha/api';

    /**
     * Constructor
     * define private and public key for requests.
     *
     * @param string $public_key  key to use as public key
     * @param string $private_key key to use as private key
     * @param bool   $init_curl   init curl instance
     *
     * @throws InvalidArgumentException
     *
     * @return reCaptcha
     */
    public function __construct($public_key, $private_key, $init_curl = true)
    {
        $this->public_key = $public_key;
        $this->private_key = $private_key;
        if (empty($this->public_key) || empty($this->private_key)) {
            throw new InvalidArgumentException('Invalid private / public key.');
        }

        if ($init_curl) {
            $this->ch = self::_initCurl();
        }
    }

    /**
     * Destructor
     * clean up opened curl instance
     *
     * @return void
     */
    public function __destruct()
    {
        curl_close($this->ch);
    }

    /**
     * init global curl object
     *
     * @return resource curl instance
     */
    private static function _initCurl()
    {
        $ch = curl_init();
        curl_setopt_array($ch, array(
            CURLOPT_HEADER => false,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_POST => true
        ));
        return $ch;
    }

    /**
     * send post call to remote api server
     *
     * @param string $url  url to send call to
     * @param array  $data post parameter for call
     *
     * @throws RuntimeException
     *
     * @return string result of post call
     */
    protected function _call($url, $data = array())
    {
        curl_setopt_array($this->ch, array(
            CURLOPT_URL => $url,
            CURLOPT_POSTFIELDS => $data
        ));

        $result = curl_exec($this->ch);
        if ($result === false) {
            throw new RuntimeException(curl_error($this->ch), curl_errno($this->ch));
        }

        return $result;
    }
}

/**
 * Google reCaptcha API Class
 *
 * @license BSD http://www.opensource.org/licenses/bsd-license.php
 */
class reCaptcha extends reCaptchaBase {
    /**
     * error message of API if response validation failed
     *
     * @var string
     */
    private $error;

    /**
     * Gets the challenge HTML (javascript and non-javascript version).
     * This is called from the browser, and the resulting reCAPTCHA HTML widget
     * is embedded within the HTML form it was called from.
     *
     * @param string  $error   The error given by reCAPTCHA (optional, default is null)
     * @param boolean $use_ssl Should the request be made over ssl? (optional, default is false)
     * @param array   $options List of options to set to reCatpcha JavaScript engine

     * @return string - The HTML to be embedded in the user's form.
     */
    public function form($error = false, $use_ssl = false, $options = array())
    {
        $out = '';
        $url = 'http' . ($use_ssl ? 's' : '') . '://' . self::$api_server;

        if (!empty($options)) {
            $out .= '<script type="text/javascript">' .
                    'var RecaptchaOptions = ' . json_encode($options) . ';</script>';
        }

        $out .= '<script type="text/javascript" src="' . $url . '/challenge?k=' . $this->public_key .
               ($error ? '&error=' . urlencode($error) : '') . '"></script>';

        $out .= '<noscript>' .
                '<iframe src="' . $url . '/noscript?k=' . $this->public_key .
                ($error ? '&error=' . urlencode($error) : '') .
                '" height="300" width="500" frameborder="0"></iframe><br/>' .
                '<textarea name="recaptcha_challenge_field" rows="3" cols="40"></textarea>' .
                '<input type="hidden" name="recaptcha_response_field" value="manual_challenge">' .
                '</noscript>';

        return $out;
    }

    /**
      * Calls an HTTP POST function to verify if the user's guess was correct
      *
      * @param string $remote_ip    client remote ip, needed for validation
      * @param string $challenge    api chalange
      * @param string $response     api response
      * @param array  $extra_params an array of extra variables to post to the server
      *
      * @throws InvalidArgumentException
      * @throws UnexpectedValueException
      *
      * @return bool True if valid answer
      */
    public function check_answer($remote_ip, $challenge, $response, $extra_params = array())
    {
        $this->error = '';
        if (empty($remote_ip)) {
            throw new InvalidArgumentException('For security reasons, you must pass the remote IP to reCAPTCHA');
        }

        // discard spam submissions
        if (empty($challenge) || empty($response)) {
            $this->error = 'incorrect-captcha-sol';
            return false;
        }

        $res = $this->_call('http://' . self::$api_server . '/verify',
            array_merge(array(
                'privatekey' => $this->private_key,
                'remoteip' => $remote_ip,
                'challenge' => $challenge,
                'response' => $response
            ), $extra_params)
        );

        if (empty($res)) {
            throw new \UnexpectedValueException('Invalid API Response.');
        }

        $answers = explode("\n", $res, 2);
        if (empty($answers)) {
            throw new \UnexpectedValueException('Invalid API Response.');
        }

        if (trim($answers[0]) == 'true') {
            return true;
        }
        $this->error = $answers[1];
        return false;
    }

    /**
     * get API error string
     *
     * @return string
     */
    public function getError() {
        return $this->error;
    }
}

/**
 * Google MailHide API Class
 *
 * @license BSD http://www.opensource.org/licenses/bsd-license.php
 */
class MailHide extends reCaptchaBase
{
    /**
     * Custom constructor to disable init of curl
     *
     * @param string $public_key  key to use as public key
     * @param string $private_key key to use as private key
     *
     * @throw InvalidArgumentException if private/public key missing
     *
     * @return reCaptcha
     */
    public function __construct($public_key, $private_key) {
        return parent::__construct($public_key, $private_key, false);
    }

    /**
     * generated AES padding
     *
     * @param string $val string to fill
     *
     * @return string filled string
     */
    private function _aes_pad($val)
    {
        $block_size = 16;
        $numpad     = $block_size - (strlen($val) % $block_size);
        return str_pad($val, strlen($val) + $numpad, chr($numpad));
    }

    /**
     * AES Encrypt value by given key
     *
     * @param string $val value to encrypt
     * @param string $ky  key to use
     *
     * @return string encrypted result
     */
    private function _aes_encrypt($val, $ky)
    {
        $mode = MCRYPT_MODE_CBC;
        $enc  = MCRYPT_RIJNDAEL_128;
        $val  = $this->aes_pad($val);
        return mcrypt_encrypt($enc, $ky, $val, $mode, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0");
    }


    /**
     * convert encrypted mail to base64 encoded
     *
     * @param string $x input to convert
     *
     * @return string converted base64
     */
    private function _get_mailhide_urlbase64($x)
    {
        return strtr(base64_encode($x), '+/', '-_');
    }

    /**
     * gets the reCAPTCHA Mailhide url for a given email, public key and private key
     *
     * @param string $email email to use
     *
     * @return string url of google recaptcha api
     */
    private function _get_mailhide_url($email)
    {
        $ky         = pack('H*', $this->private_key);
        $crypt_mail = $this->_aes_encrypt($email, $ky);
        return 'http://www.google.com/recaptcha/mailhide/d?k=' . $this->public_key .
               '&c=' . $this->_get_mailhide_urlbase64($crypt_mail);
    }

    /**
     * gets the parts of the email to expose to the user.
     * eg, given johndoe@example,com return ["john", "example.com"].
     * the email is then displayed as john...@example.com
     *
     * @param string $email email to explode
     *
     * @return array of elements.
     */
    private function _get_mailhide_email_parts($email)
    {
        $arr = preg_split("/@/", $email);
        if (strlen($arr[0]) <= 4) {
            $arr[0] = substr($arr[0], 0, 1);
        } elseif (strlen($arr[0]) <= 6) {
            $arr[0] = substr($arr[0], 0, 3);
        } else {
            $arr[0] = substr($arr[0], 0, 4);
        }
        return $arr;
    }

    /**
     * Gets html to display an email address given a public an private key.
     * to get a key, go to:
     *
     * @see http://www.google.com/recaptcha/mailhide/apikey
     *
     * @param string $email email to convert
     *
     * @return string converted version
     */
    public function email($email)
    {
        $email_parts = $this->_get_mailhide_email_parts($email);
        $url         = $this->_get_mailhide_url($email);
        return htmlentities($email_parts[0]) .
               '<a href="' . htmlentities($url) . '" onclick="window.open(\'' . htmlentities($url) .
               '\', \'\', \'toolbar=0,scrollbars=0,location=0,statusbar=0,menubar=0,resizable=0,'.
               'width=500,height=300\'); return false;" title="Reveal this e-mail address">...</a>@' .
               htmlentities($email_parts[1]);
    }
}
