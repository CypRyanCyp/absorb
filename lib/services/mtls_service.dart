import 'dart:convert';
import 'dart:io';
import 'package:flutter/foundation.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:basic_utils/basic_utils.dart';
import 'package:just_audio/just_audio.dart' show AudioPlayer;

/// Manages a PKCS12 client certificate for mTLS-protected servers.
///
/// The encrypted P12 bytes, password, and filename are persisted to platform
/// secure storage (Android Keystore / iOS Keychain) and parsed on startup into
/// a Dart [SecurityContext] that the global [HttpOverrides] injects into every
/// HttpClient. The Android audio path consumes the raw bytes through a
/// method-channel call into ExoPlayer.
///
/// Security: the raw P12 bytes and password are never kept in a long-lived
/// field. After parsing, the private key survives only inside the native
/// [SecurityContext] (Dart TLS) and ExoPlayer's SSLContext (audio). Code that
/// needs the raw bytes again re-reads them transiently from secure storage so
/// they become garbage-collectable the moment the call returns.
class MtlsService {
  static const _storage = FlutterSecureStorage(
    aOptions: AndroidOptions(encryptedSharedPreferences: true),
  );

  static const _kP12Base64 = 'mtls_p12_b64';
  static const _kPassword = 'mtls_p12_password';
  static const _kFilename = 'mtls_p12_filename';

  static SecurityContext? _securityContext;
  static String? _p12Filename;

  static SecurityContext? get securityContext => _securityContext;
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
      _parse(base64.decode(b64), pwd);
      _p12Filename = fname;
    } catch (e) {
      debugPrint('[mTLS] init failed: $e');
    }
  }

  /// Import a P12 file. Throws on wrong password or parse error; on success
  /// the cert is activated in-memory, persisted to secure storage, and pushed
  /// to the ExoPlayer audio path.
  static Future<void> importP12(
      Uint8List bytes, String password, String filename) async {
    // Parse first — any failure aborts before we touch storage.
    _parse(bytes, password);
    _p12Filename = filename;
    await _storage.write(key: _kP12Base64, value: base64.encode(bytes));
    await _storage.write(key: _kPassword, value: password);
    await _storage.write(key: _kFilename, value: filename);
    await configureAudioPlayer();
  }

  /// Remove the stored cert and clear all in-memory and ExoPlayer state.
  static Future<void> remove() async {
    _securityContext = null;
    _p12Filename = null;
    await _storage.delete(key: _kP12Base64);
    await _storage.delete(key: _kPassword);
    await _storage.delete(key: _kFilename);
    if (Platform.isAndroid) {
      await AudioPlayer.configureMtls(null, null);
    }
  }

  /// Push the configured client cert to ExoPlayer (Android audio path). Reads
  /// the P12 from secure storage transiently so the raw bytes never live in a
  /// long-lived field. No-op on non-Android or when no cert is configured.
  static Future<void> configureAudioPlayer() async {
    if (!Platform.isAndroid || _securityContext == null) return;
    final b64 = await _storage.read(key: _kP12Base64);
    if (b64 == null) return;
    final pwd = await _storage.read(key: _kPassword) ?? '';
    await AudioPlayer.configureMtls(base64.decode(b64), pwd);
  }

  /// Parse [bytes] into [_securityContext]. The bytes/password are consumed
  /// here and intentionally not retained.
  static void _parse(Uint8List bytes, String password) {
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
  }

  static bool _isCertificate(String pem) => pem.contains('BEGIN CERTIFICATE');

  static bool _isPrivateKey(String pem) =>
      pem.contains('BEGIN PRIVATE KEY') ||
      pem.contains('BEGIN RSA PRIVATE KEY') ||
      pem.contains('BEGIN EC PRIVATE KEY');
}
