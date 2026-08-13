<?php


class TokenBucket
{
    private float $capacity = 1.0;
    private float $fill_rate = 1.0;

    function __construct(float $capacity, float $fill_rate)
    {
        $this->capacity = $capacity;
        $this->fill_rate = $fill_rate;
    }


    public function consume_token(string $ip): bool
    {
        $hash = hash('sha1', $ip);
        $file_path = "/tmp/tocket_bucket_{$hash}.json";

        $file = fopen($file_path, 'c+');
        if (!$file) {
            return false;
        }

        if (!flock($file, LOCK_EX)) {
            fclose($file);
            return false;
        }

        $current_time = hrtime()[0];

        $file_size = filesize($file_path);
        if ($file_size > 0) {
            $content = fread($file, $file_size);
            $data = json_decode($content, true);
            $tokens = floatval($data['token_count'] ?? $this->capacity);
            $updated_at = $data['updated_at'] ?? $current_time;
        } else {
            $tokens = $this->capacity;
            $updated_at = $current_time;
        }

        $elapsed = $current_time - $updated_at;
        if ($elapsed > 0) {
            $tokens = floatval(min($this->capacity, $tokens + ($elapsed * $this->fill_rate)));
            $updated_at = $current_time;
        }

        if ($tokens >= 1.0) {
            $tokens -= 1.0;
            $allowed = true;
        } else {
            $allowed = false;
        }

        ftruncate($file, 0);
        rewind($file);
        fwrite($file, json_encode([
            'token_count'   => floatval($tokens),
            'updated_at'    => $updated_at,
            'ip'            => $ip
        ]));

        flock($file, LOCK_UN);
        fclose($file);

        return $allowed;
    }
}