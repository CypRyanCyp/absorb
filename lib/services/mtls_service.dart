import 'dart:convert';
import 'dart:io';
import 'package:flutter/foundation.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:basic_utils/basic_utils.dart';

class MtlsService {
  static const _storage = FlutterSecureStorage(
    aOptions: AndroidOptions(encryptedSharedPreferences: true),
  );

  static const _kP12Base64 = 'mtls_p12_b64';
  static const _kPassword = 'mtls_p12_password';
  static const _kFilename = 'mtls_p12_filename';

  static SecurityContext? _securityContext;
  static List<int>? _p12Bytes;
  static String? _p12Password;
  static String? _p12Filename;

  static SecurityContext? get securityContext => _securityContext;
  static List<int>? get p12Bytes => _p12Bytes;
  static String? get p12Password => _p12Password;
  static String? get p12Filename => _p12Filename;
  static bool get hasCert => _securityContext != null;

  /// Load and parse stored cert at startup. Silently skips on error.
  static Future<void> init() async {
    try {
      final b64 = await _storage.read(key: _kP12Base64);
      final pwd = await _storage.read(key: _kPassword);
      final fname = await _storage.read(key: _kFilename);
      if (b64 == null) return;
      final bytes = base64.decode(b64);
      await _parseAndStore(bytes, pwd ?? '', fname ?? '');
    } catch (e) {
      debugPrint('[mTLS] init failed: $e');
    }
  }

  /// Import a P12 file. Throws on wrong password or parse error.
  static Future<void> importP12(
      List<int> bytes, String password, String filename) async {
    // Parse first — throws if password is wrong or file is invalid
    await _parseAndStore(bytes, password, filename);
    // Persist only after successful parse
    await _storage.write(key: _kP12Base64, value: base64.encode(bytes));
    await _storage.write(key: _kPassword, value: password);
    await _storage.write(key: _kFilename, value: filename);
  }

  static Future<void> _parseAndStore(
      List<int> bytes, String password, String filename) async {
    // Returns a list of PEM strings: private key + certificate(s)
    final pems = Pkcs12Utils.parsePkcs12(
      Uint8List.fromList(bytes),
      password: password.isEmpty ? null : password,
    );

    if (pems.isEmpty) {
      throw Exception('No data found in P12 file');
    }

    // Separate the private key PEM from certificate PEMs
    final certPems = pems.where(_isCertificate).toList();
    final keyPems = pems.where(_isPrivateKey).toList();

    if (certPems.isEmpty) throw Exception('No certificate found in P12 file');
    if (keyPems.isEmpty) throw Exception('No private key found in P12 file');

    final certPem = certPems.join('\n');
    final keyPem = keyPems.first;

    final ctx = SecurityContext(withTrustedRoots: true);
    ctx.useCertificateChainBytes(utf8.encode(certPem));
    ctx.usePrivateKeyBytes(utf8.encode(keyPem));

    _securityContext = ctx;
    _p12Bytes = bytes;
    _p12Password = password;
    _p12Filename = filename;
  }

  static bool _isCertificate(String pem) =>
      pem.contains('BEGIN CERTIFICATE');

  static bool _isPrivateKey(String pem) =>
      pem.contains('BEGIN PRIVATE KEY') ||
      pem.contains('BEGIN RSA PRIVATE KEY') ||
      pem.contains('BEGIN EC PRIVATE KEY');

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
}
