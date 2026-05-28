import 'dart:convert';
import 'dart:io';
import 'package:flutter/foundation.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:basic_utils/basic_utils.dart';

/// Manages a PKCS12 client certificate for mTLS-protected servers.
///
/// The encrypted P12 bytes, password, and filename are persisted to
/// platform secure storage (Android Keystore / iOS Keychain) and parsed on
/// startup into a Dart [SecurityContext] that the global [HttpOverrides]
/// injects into every HttpClient. The Android audio path consumes the raw
/// bytes through a method-channel call into ExoPlayer.
class MtlsService {
  static const _storage = FlutterSecureStorage(
    aOptions: AndroidOptions(encryptedSharedPreferences: true),
  );

  static const _kP12Base64 = 'mtls_p12_b64';
  static const _kPassword = 'mtls_p12_password';
  static const _kFilename = 'mtls_p12_filename';

  static SecurityContext? _securityContext;
  static Uint8List? _p12Bytes;
  static String? _p12Password;
  static String? _p12Filename;

  static SecurityContext? get securityContext => _securityContext;
  static Uint8List? get p12Bytes => _p12Bytes;
  static String? get p12Password => _p12Password;
  static String? get p12Filename => _p12Filename;
  static bool get hasCert => _securityContext != null;

  /// Load and parse the stored cert at startup. Silently no-ops if no cert
  /// is stored or the stored data fails to parse (e.g. password changed
  /// out-of-band) — the user can re-import via Settings.
  static Future<void> init() async {
    try {
      final b64 = await _storage.read(key: _kP12Base64);
      if (b64 == null) return;
      final pwd = await _storage.read(key: _kPassword) ?? '';
      final fname = await _storage.read(key: _kFilename);
      await _parseAndStore(base64.decode(b64), pwd, fname);
    } catch (e) {
      debugPrint('[mTLS] init failed: $e');
    }
  }

  /// Import a P12 file. Throws on wrong password or parse error; on success
  /// the cert is activated in-memory and persisted to secure storage.
  static Future<void> importP12(
      Uint8List bytes, String password, String filename) async {
    // Parse first — any failure aborts before we touch storage.
    await _parseAndStore(bytes, password, filename);
    await _storage.write(key: _kP12Base64, value: base64.encode(bytes));
    await _storage.write(key: _kPassword, value: password);
    await _storage.write(key: _kFilename, value: filename);
  }

  /// Remove the stored cert and clear all in-memory state.
  static Future<void> remove() async {
    _securityContext = null;
    _p12Bytes = null;
    _p12Password = null;
    _p12Filename = null;
    await _storage.delete(key: _kP12Base64);
    await _storage.delete(key: _kPassword);
    await _storage.delete(key: _kFilename);
  }

  static Future<void> _parseAndStore(
      Uint8List bytes, String password, String? filename) async {
    // parsePkcs12 treats null as "no password"; an empty string triggers the
    // password-formatting path and fails on unencrypted P12s.
    final pems = Pkcs12Utils.parsePkcs12(
      bytes,
      password: password.isEmpty ? null : password,
    );

    final certPems = pems.where(_isCertificate).toList();
    final keyPems = pems.where(_isPrivateKey).toList();
    if (certPems.isEmpty) throw Exception('No certificate found in P12 file');
    if (keyPems.isEmpty) throw Exception('No private key found in P12 file');

    final ctx = SecurityContext(withTrustedRoots: true);
    ctx.useCertificateChainBytes(utf8.encode(certPems.join('\n')));
    ctx.usePrivateKeyBytes(utf8.encode(keyPems.first));

    _securityContext = ctx;
    _p12Bytes = bytes;
    _p12Password = password;
    _p12Filename = filename;
  }

  static bool _isCertificate(String pem) => pem.contains('BEGIN CERTIFICATE');

  static bool _isPrivateKey(String pem) =>
      pem.contains('BEGIN PRIVATE KEY') ||
      pem.contains('BEGIN RSA PRIVATE KEY') ||
      pem.contains('BEGIN EC PRIVATE KEY');
}
