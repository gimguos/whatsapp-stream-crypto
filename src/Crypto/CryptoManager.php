<?php

namespace WhatsAppStream\Crypto;

use WhatsAppStream\Enum\MediaType;

/**
 * Класс, отвечающий за все криптографические операции в системе
 * Реализует алгоритмы шифрования, используемые в WhatsApp
 */
class CryptoManager
{
    /**
     * Длина расширенного ключа в байтах (16 + 32 + 32 + 32)
     * 16 байт для IV
     * 32 байта для ключа шифрования
     * 32 байта для ключа MAC
     * 32 байта для refKey (не используется)
     */
    private const EXPANDED_KEY_LENGTH = 112;

    /**
     * Длина вектора инициализации (IV) в байтах
     */
    private const IV_LENGTH = 16;

    /**
     * Длина ключа шифрования в байтах
     */
    private const CIPHER_KEY_LENGTH = 32;

    /**
     * Длина ключа MAC в байтах
     */
    private const MAC_KEY_LENGTH = 32;

    /**
     * Длина MAC в байтах (усеченная версия полного MAC)
     */
    private const MAC_LENGTH = 10;

    /**
     * Размер чанка для стриминга (64KB)
     */
    private const CHUNK_SIZE = 65536;

    /**
     * Расширяет mediaKey до 112 байт используя HKDF с SHA-256
     * и разделяет его на IV, ключ шифрования и ключ MAC
     *
     * @param string $mediaKey 32-байтный ключ
     * @param MediaType $type Тип медиа для контекстной информации
     * @return array Массив с IV, ключом шифрования и ключом MAC
     */
    public function expandMediaKey(string $mediaKey, MediaType $type): array
    {
        // Шаг 1: HKDF Extract
        $salt = str_repeat("\0", 32); // Нулевая соль
        $prk = hash_hmac('sha256', $mediaKey, $salt, true);

        // Шаг 2: HKDF Expand
        $info = $type->value; // Используем тип медиа как info
        $expandedKey = '';
        $previousBlock = '';
        $blockIndex = 1;

        while (strlen($expandedKey) < self::EXPANDED_KEY_LENGTH) {
            $hmac = hash_hmac(
                'sha256',
                $previousBlock . $info . chr($blockIndex),
                $prk,
                true
            );
            $previousBlock = $hmac;
            $expandedKey .= $hmac;
            $blockIndex++;
        }

        $expandedKey = substr($expandedKey, 0, self::EXPANDED_KEY_LENGTH);

        return [
            'iv' => substr($expandedKey, 0, self::IV_LENGTH),
            'cipherKey' => substr($expandedKey, self::IV_LENGTH, self::CIPHER_KEY_LENGTH),
            'macKey' => substr($expandedKey, self::IV_LENGTH + self::CIPHER_KEY_LENGTH, self::MAC_KEY_LENGTH),
        ];
    }

    /**
     * Шифрует данные используя AES-256-CBC
     *
     * @param string $data Данные для шифрования
     * @param string $iv Вектор инициализации
     * @param string $cipherKey Ключ шифрования
     * @return string Зашифрованные данные
     */
    public function encrypt(string $data, string $iv, string $cipherKey): string
    {
        return openssl_encrypt(
            $data,
            'aes-256-cbc',
            $cipherKey,
            OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
            $iv
        );
    }

    /**
     * Расшифровывает данные используя AES-256-CBC
     *
     * @param string $data Зашифрованные данные
     * @param string $iv Вектор инициализации
     * @param string $cipherKey Ключ шифрования
     * @return string Расшифрованные данные
     */
    public function decrypt(string $data, string $iv, string $cipherKey): string
    {
        return openssl_decrypt(
            $data,
            'aes-256-cbc',
            $cipherKey,
            OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
            $iv
        );
    }

    /**
     * Вычисляет MAC для данных используя HMAC-SHA256
     * и усекает результат до 10 байт
     *
     * @param string $data Данные для вычисления MAC
     * @param string $macKey Ключ для MAC
     * @return string 10-байтный MAC
     */
    public function calculateMac(string $data, string $macKey): string
    {
        return substr(
            hash_hmac('sha256', $data, $macKey, true),
            0,
            self::MAC_LENGTH
        );
    }

    /**
     * Проверяет MAC для данных
     *
     * @param string $data Данные для проверки
     * @param string $expectedMac Ожидаемый MAC
     * @param string $macKey Ключ для MAC
     * @return bool true если MAC верный, false в противном случае
     */
    public function verifyMac(string $data, string $expectedMac, string $macKey): bool
    {
        $calculatedMac = $this->calculateMac($data, $macKey);
        return hash_equals($expectedMac, $calculatedMac);
    }

    /**
     * Генерирует информацию для стриминга (sidecar)
     * Разбивает данные на чанки по 64KB и вычисляет MAC для каждого чанка
     *
     * @param string $data Данные для генерации sidecar
     * @param string $macKey Ключ для MAC
     * @return string Конкатенация MAC'ов всех чанков
     */
    public function generateStreamingSidecar(string $data, string $macKey): string
    {
        $chunks = str_split($data, self::CHUNK_SIZE);
        $sidecar = '';
        
        foreach ($chunks as $chunk) {
            $sidecar .= $this->calculateMac($chunk, $macKey);
        }
        
        return $sidecar;
    }
} 