using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net.Sockets;
using System.Net.WebSockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Media.Effects;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;
using System.Windows.Threading;

namespace CipherNative
{
    public static class Program
    {
        public static Process ServerProcess = null;
        public static string AppDir;

        [DllImport("user32.dll")]
        public static extern bool SetProcessDPIAware();

        [STAThread]
        public static void Main(string[] args)
        {
            try { SetProcessDPIAware(); } catch { }

            AppDir = AppDomain.CurrentDomain.BaseDirectory;
            string serverScript = System.IO.Path.Combine(AppDir, "server", "server.js");

            bool isServerRunning = false;
            try
            {
                using (var client = new TcpClient())
                {
                    var result = client.BeginConnect("127.0.0.1", 8080, null, null);
                    isServerRunning = result.AsyncWaitHandle.WaitOne(300);
                }
            }
            catch { }

            if (!isServerRunning && File.Exists(serverScript))
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "node.exe",
                    Arguments = "\"" + serverScript + "\"",
                    WorkingDirectory = AppDir,
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    WindowStyle = ProcessWindowStyle.Hidden
                };
                try
                {
                    ServerProcess = Process.Start(psi);
                    Thread.Sleep(600);
                }
                catch { }
            }

            AppDomain.CurrentDomain.ProcessExit += delegate
            {
                if (ServerProcess != null && !ServerProcess.HasExited)
                {
                    try { ServerProcess.Kill(); } catch { }
                }
            };

            string initialUser = "\u0410\u043B\u0438\u0441\u0430"; // Алиса
            if (args != null && args.Length > 0 && !string.IsNullOrEmpty(args[0]))
            {
                string a = args[0].Trim();
                if (a.Equals("Bob", StringComparison.OrdinalIgnoreCase) || a.IndexOf("Bob") >= 0 || a.IndexOf("\u0411\u043E\u0431") >= 0 || a == "2")
                {
                    initialUser = "\u0411\u043E\u0431"; // Боб
                }
                else if (a.Equals("Alice", StringComparison.OrdinalIgnoreCase) || a.IndexOf("Alice") >= 0 || a.IndexOf("\u0410\u043B\u0438\u0441\u0430") >= 0 || a == "1")
                {
                    initialUser = "\u0410\u043B\u0438\u0441\u0430"; // Алиса
                }
                else
                {
                    initialUser = a;
                }
            }

            try
            {
                var app = new Application();
                var mainWindow = new MainWindow(initialUser);
                app.Run(mainWindow);
            }
            catch (Exception ex)
            {
                try
                {
                    File.WriteAllText(System.IO.Path.Combine(AppDir ?? "", "crash.log"), ex.ToString(), Encoding.UTF8);
                }
                catch { }
            }
        }
    }

    public enum ToastType
    {
        Info,
        Success,
        Warning,
        Error
    }

    // =========================================================================
    // E2EE КРИПТОГРАФИЯ (NIST P-256 ECDH + AES-256-GCM, 100% совместимо с WebCrypto/Android)
    // =========================================================================
    public class UserIdentity
    {
        public string Id { get; set; }
        public string Name { get; set; }
        public string PublicKeyB64 { get; set; }
        public string PrivateKeyB64 { get; set; }
        public string ServerUrl { get; set; }
        public string ServerSecret { get; set; }
    }

    public static class NativeCrypto
    {
        [DllImport("bcrypt.dll")]
        private static extern int BCryptOpenAlgorithmProvider(out IntPtr phAlgorithm, [MarshalAs(UnmanagedType.LPWStr)] string pszAlgId, string pszImplementation, uint dwFlags);

        [DllImport("bcrypt.dll")]
        private static extern int BCryptSetProperty(IntPtr hObject, [MarshalAs(UnmanagedType.LPWStr)] string pszProperty, [MarshalAs(UnmanagedType.LPWStr)] string pbInput, int cbInput, uint dwFlags);

        [DllImport("bcrypt.dll")]
        private static extern int BCryptGenerateSymmetricKey(IntPtr hAlgorithm, out IntPtr phKey, IntPtr pbKeyObject, int cbKeyObject, byte[] pbSecret, int cbSecret, uint dwFlags);

        [DllImport("bcrypt.dll")]
        private static extern int BCryptEncrypt(IntPtr hKey, byte[] pbInput, int cbInput, ref BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO pPaddingInfo, byte[] pbIV, int cbIV, byte[] pbOutput, int cbOutput, out int pcbResult, uint dwFlags);

        [DllImport("bcrypt.dll")]
        private static extern int BCryptDecrypt(IntPtr hKey, byte[] pbInput, int cbInput, ref BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO pPaddingInfo, byte[] pbIV, int cbIV, byte[] pbOutput, int cbOutput, out int pcbResult, uint dwFlags);

        [DllImport("bcrypt.dll")]
        private static extern int BCryptDestroyKey(IntPtr hKey);

        [DllImport("bcrypt.dll")]
        private static extern int BCryptCloseAlgorithmProvider(IntPtr hAlgorithm, uint dwFlags);

        [StructLayout(LayoutKind.Sequential)]
        private struct BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO
        {
            public int cbSize;
            public uint dwInfoVersion;
            public IntPtr pbNonce;
            public int cbNonce;
            public IntPtr pbAuthData;
            public int cbAuthData;
            public IntPtr pbTag;
            public int cbTag;
            public IntPtr pbMacContext;
            public int cbMacContext;
            public int cbAAD;
            public long cbData;
            public uint dwFlags;
        }

        // Преобразование стандартных 65 байт ANSI X9.62 (0x04 || X || Y) в блоб Windows CNG EccPublicBlob
        private static byte[] ConvertRawToCngPublicBlob(byte[] rawPub)
        {
            if (rawPub == null) throw new ArgumentNullException("rawPub");
            if (rawPub.Length == 72 && rawPub[0] == 0x45 && rawPub[1] == 0x43 && rawPub[2] == 0x4B && rawPub[3] == 0x31) return rawPub; // Уже правильный CNG P-256 блоб
            if (rawPub.Length != 65 && rawPub.Length != 64)
            {
                throw new ArgumentException("Недопустимый открытый ключ: ожидается 65 байт NIST P-256 (получено: " + rawPub.Length + " байт). Возможно, ключ контакта устарел.");
            }
            int offset = (rawPub.Length == 65 && rawPub[0] == 0x04) ? 1 : 0;
            byte[] blob = new byte[72];
            blob[0] = 0x45; blob[1] = 0x43; blob[2] = 0x4B; blob[3] = 0x31; // BCRYPT_ECDH_PUBLIC_P256_MAGIC
            blob[4] = 0x20; blob[5] = 0x00; blob[6] = 0x00; blob[7] = 0x00; // 32 bytes
            Buffer.BlockCopy(rawPub, offset, blob, 8, 64);
            return blob;
        }

        // Извлечение стандартных 65 байт ANSI X9.62 из Windows CNG EccPublicBlob
        private static byte[] ConvertCngToRawPublic(byte[] cngBlob)
        {
            byte[] raw = new byte[65];
            raw[0] = 0x04;
            Buffer.BlockCopy(cngBlob, 8, raw, 1, 64);
            return raw;
        }

        public static UserIdentity LoadOrGenerateIdentity(string userName)
        {
            string appData = System.IO.Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "CipherNative"
            );
            Directory.CreateDirectory(appData);
            string idFile = System.IO.Path.Combine(appData, "identity_p256_" + userName + ".json");

            var js = new JavaScriptSerializer { MaxJsonLength = int.MaxValue };
            if (File.Exists(idFile))
            {
                try
                {
                    string raw = File.ReadAllText(idFile, Encoding.UTF8);
                    var id = js.Deserialize<UserIdentity>(raw);
                    if (id != null && !string.IsNullOrEmpty(id.PrivateKeyB64) && !string.IsNullOrEmpty(id.PublicKeyB64))
                    {
                        return id;
                    }
                }
                catch { }
            }

            using (var ecdh = new ECDiffieHellmanCng(256))
            {
                ecdh.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
                ecdh.HashAlgorithm = CngAlgorithm.Sha256;

                byte[] cngPub = ecdh.Key.Export(CngKeyBlobFormat.EccPublicBlob);
                byte[] rawPub65 = ConvertCngToRawPublic(cngPub);
                byte[] privBytes = ecdh.Key.Export(CngKeyBlobFormat.GenericPrivateBlob);

                string idHex;
                using (var sha = SHA256.Create())
                {
                    byte[] hash = sha.ComputeHash(rawPub65);
                    var sb = new StringBuilder();
                    foreach (byte b in hash) sb.Append(b.ToString("x2"));
                    idHex = sb.ToString();
                }

                var identity = new UserIdentity
                {
                    Id = idHex,
                    Name = userName,
                    PublicKeyB64 = Convert.ToBase64String(rawPub65),
                    PrivateKeyB64 = Convert.ToBase64String(privBytes)
                };

                File.WriteAllText(idFile, js.Serialize(identity), Encoding.UTF8);
                return identity;
            }
        }

        public static byte[] AesGcmEncrypt(byte[] key, byte[] iv, byte[] plaintext)
        {
            IntPtr hAlg, hKey;
            BCryptOpenAlgorithmProvider(out hAlg, "AES", null, 0);
            string chainMode = "ChainingModeGCM\0";
            BCryptSetProperty(hAlg, "ChainingMode", chainMode, chainMode.Length * 2, 0);
            BCryptGenerateSymmetricKey(hAlg, out hKey, IntPtr.Zero, 0, key, key.Length, 0);

            byte[] tag = new byte[16];
            byte[] cipher = new byte[plaintext.Length];

            GCHandle nonceHandle = GCHandle.Alloc(iv, GCHandleType.Pinned);
            GCHandle tagHandle = GCHandle.Alloc(tag, GCHandleType.Pinned);

            var info = new BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO();
            info.cbSize = Marshal.SizeOf(typeof(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO));
            info.dwInfoVersion = 1;
            info.pbNonce = nonceHandle.AddrOfPinnedObject();
            info.cbNonce = iv.Length;
            info.pbTag = tagHandle.AddrOfPinnedObject();
            info.cbTag = tag.Length;

            int written;
            BCryptEncrypt(hKey, plaintext, plaintext.Length, ref info, null, 0, cipher, cipher.Length, out written, 0);

            nonceHandle.Free();
            tagHandle.Free();
            BCryptDestroyKey(hKey);
            BCryptCloseAlgorithmProvider(hAlg, 0);

            // WebCrypto standard format: ciphertext || 16-byte tag
            byte[] combined = new byte[cipher.Length + 16];
            Buffer.BlockCopy(cipher, 0, combined, 0, cipher.Length);
            Buffer.BlockCopy(tag, 0, combined, cipher.Length, 16);
            return combined;
        }

        public static byte[] AesGcmDecrypt(byte[] key, byte[] iv, byte[] cipherAndTag)
        {
            IntPtr hAlg, hKey;
            BCryptOpenAlgorithmProvider(out hAlg, "AES", null, 0);
            string chainMode = "ChainingModeGCM\0";
            BCryptSetProperty(hAlg, "ChainingMode", chainMode, chainMode.Length * 2, 0);
            BCryptGenerateSymmetricKey(hAlg, out hKey, IntPtr.Zero, 0, key, key.Length, 0);

            int cipherLen = cipherAndTag.Length - 16;
            byte[] cipher = new byte[cipherLen];
            byte[] tag = new byte[16];
            Buffer.BlockCopy(cipherAndTag, 0, cipher, 0, cipherLen);
            Buffer.BlockCopy(cipherAndTag, cipherLen, tag, 0, 16);

            byte[] decrypted = new byte[cipherLen];
            GCHandle nonceHandle = GCHandle.Alloc(iv, GCHandleType.Pinned);
            GCHandle tagHandle = GCHandle.Alloc(tag, GCHandleType.Pinned);

            var decInfo = new BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO();
            decInfo.cbSize = Marshal.SizeOf(typeof(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO));
            decInfo.dwInfoVersion = 1;
            decInfo.pbNonce = nonceHandle.AddrOfPinnedObject();
            decInfo.cbNonce = iv.Length;
            decInfo.pbTag = tagHandle.AddrOfPinnedObject();
            decInfo.cbTag = tag.Length;

            int decWritten;
            int status = BCryptDecrypt(hKey, cipher, cipher.Length, ref decInfo, null, 0, decrypted, decrypted.Length, out decWritten, 0);

            nonceHandle.Free();
            tagHandle.Free();
            BCryptDestroyKey(hKey);
            BCryptCloseAlgorithmProvider(hAlg, 0);

            if (status != 0) throw new CryptographicException("AES-GCM integrity check failed (status: 0x" + status.ToString("X") + ")");
            return decrypted;
        }

        public static Dictionary<string, string> EncryptEnvelope(string recipientPubB64, string jsonPayload)
        {
            using (var ephEcdh = new ECDiffieHellmanCng(256))
            {
                ephEcdh.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
                ephEcdh.HashAlgorithm = CngAlgorithm.Sha256;

                byte[] ephCngPub = ephEcdh.Key.Export(CngKeyBlobFormat.EccPublicBlob);
                byte[] ephRaw65 = ConvertCngToRawPublic(ephCngPub);
                string ephPubB64 = Convert.ToBase64String(ephRaw65);

                byte[] recipientRaw = Convert.FromBase64String(recipientPubB64);
                byte[] recipientCngBlob = ConvertRawToCngPublicBlob(recipientRaw);
                var recipientCngKey = CngKey.Import(recipientCngBlob, CngKeyBlobFormat.EccPublicBlob);

                byte[] sharedKey = ephEcdh.DeriveKeyMaterial(recipientCngKey);

                byte[] iv = new byte[12];
                using (var rng = new RNGCryptoServiceProvider()) rng.GetBytes(iv);

                byte[] rawPlain = Encoding.UTF8.GetBytes(jsonPayload);
                byte[] encBytes = AesGcmEncrypt(sharedKey, iv, rawPlain);

                return new Dictionary<string, string>
                {
                    { "ephemeralPub", ephPubB64 },
                    { "iv", Convert.ToBase64String(iv) },
                    { "ciphertext", Convert.ToBase64String(encBytes) }
                };
            }
        }

        public static string DecryptEnvelope(string myPrivKeyB64, Dictionary<string, object> envelope)
        {
            string ephPubB64 = envelope["ephemeralPub"].ToString();
            string ivB64 = envelope["iv"].ToString();
            string cipherB64 = envelope["ciphertext"].ToString();

            byte[] myPrivBytes = Convert.FromBase64String(myPrivKeyB64);
            CngKey myCngKey = CngKey.Import(myPrivBytes, CngKeyBlobFormat.GenericPrivateBlob);

            using (var myEcdh = new ECDiffieHellmanCng(myCngKey))
            {
                myEcdh.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
                myEcdh.HashAlgorithm = CngAlgorithm.Sha256;

                byte[] ephRaw = Convert.FromBase64String(ephPubB64);
                byte[] ephCngBlob = ConvertRawToCngPublicBlob(ephRaw);
                var ephCngKey = CngKey.Import(ephCngBlob, CngKeyBlobFormat.EccPublicBlob);

                byte[] sharedKey = myEcdh.DeriveKeyMaterial(ephCngKey);

                byte[] iv = Convert.FromBase64String(ivB64);
                byte[] rawCipher = Convert.FromBase64String(cipherB64);

                byte[] decBytes = AesGcmDecrypt(sharedKey, iv, rawCipher);
                return Encoding.UTF8.GetString(decBytes);
            }
        }
    }

    // =========================================================================
    // ГОЛОСОВАЯ ЗАПИСЬ (WIN32 WINMM)
    // =========================================================================
    public static class NativeAudio
    {
        [DllImport("winmm.dll", EntryPoint = "mciSendStringA", CharSet = CharSet.Ansi)]
        private static extern int mciSendString(string command, StringBuilder buffer, int bufferSize, IntPtr hwndCallback);

        private static string currentWavFile = null;

        public static bool StartRecording()
        {
            try
            {
                currentWavFile = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "cipher_voice_" + Guid.NewGuid().ToString("N") + ".wav");
                mciSendString("close recsound", null, 0, IntPtr.Zero);
                mciSendString("open new type waveaudio alias recsound", null, 0, IntPtr.Zero);
                mciSendString("set recsound bitspersample 16 channels 1 samplespersec 16000", null, 0, IntPtr.Zero);
                mciSendString("record recsound", null, 0, IntPtr.Zero);
                return true;
            }
            catch
            {
                return false;
            }
        }

        public static byte[] StopAndGetRecording()
        {
            try
            {
                if (string.IsNullOrEmpty(currentWavFile)) return null;
                mciSendString("save recsound " + currentWavFile, null, 0, IntPtr.Zero);
                mciSendString("close recsound", null, 0, IntPtr.Zero);

                if (File.Exists(currentWavFile))
                {
                    byte[] bytes = File.ReadAllBytes(currentWavFile);
                    try { File.Delete(currentWavFile); } catch { }
                    currentWavFile = null;
                    return bytes;
                }
            }
            catch { }
            return null;
        }

        public static void CancelRecording()
        {
            try
            {
                mciSendString("close recsound", null, 0, IntPtr.Zero);
                if (!string.IsNullOrEmpty(currentWavFile) && File.Exists(currentWavFile))
                {
                    try { File.Delete(currentWavFile); } catch { }
                }
                currentWavFile = null;
            }
            catch { }
        }

        private static MediaPlayer activePlayer = null;
        private static string currentPlayingTempFile = null;
        public static double CurrentPlaybackSpeed = 1.0;

        public static void SetPlaybackSpeed(double speed)
        {
            CurrentPlaybackSpeed = speed;
            if (activePlayer != null)
            {
                try { activePlayer.SpeedRatio = speed; } catch { }
            }
        }

        // Универсальное воспроизведение любого аудио (WAV, WebM, Ogg, MP3) через системный MediaFoundation
        public static void PlayAudioBytes(byte[] audioBytes, string extensionHint)
        {
            if (audioBytes == null || audioBytes.Length == 0) return;
            ThreadPool.QueueUserWorkItem(delegate
            {
                try
                {
                    string ext = !string.IsNullOrEmpty(extensionHint) ? extensionHint : ".wav";
                    if (!ext.StartsWith(".")) ext = "." + ext;
                    string tempFile = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "cipher_play_" + Guid.NewGuid().ToString("N") + ext);
                    File.WriteAllBytes(tempFile, audioBytes);

                    Application.Current.Dispatcher.Invoke(new Action(delegate
                    {
                        try
                        {
                            if (activePlayer != null)
                            {
                                activePlayer.Stop();
                                activePlayer.Close();
                                activePlayer = null;
                                if (!string.IsNullOrEmpty(currentPlayingTempFile) && File.Exists(currentPlayingTempFile))
                                {
                                    try { File.Delete(currentPlayingTempFile); } catch { }
                                }
                                currentPlayingTempFile = null;
                            }

                            currentPlayingTempFile = tempFile;
                            activePlayer = new MediaPlayer();
                            activePlayer.Open(new Uri(tempFile));
                            try { activePlayer.SpeedRatio = CurrentPlaybackSpeed; } catch { }
                            activePlayer.MediaEnded += delegate
                            {
                                if (activePlayer != null)
                                {
                                    activePlayer.Close();
                                    activePlayer = null;
                                }
                                if (!string.IsNullOrEmpty(tempFile) && File.Exists(tempFile))
                                {
                                    try { File.Delete(tempFile); } catch { }
                                }
                            };
                            activePlayer.MediaFailed += delegate
                            {
                                if (activePlayer != null)
                                {
                                    try { activePlayer.Close(); } catch { }
                                    activePlayer = null;
                                }
                                if (!string.IsNullOrEmpty(tempFile) && File.Exists(tempFile))
                                {
                                    try { File.Delete(tempFile); } catch { }
                                }
                                try
                                {
                                    using (var ms = new System.IO.MemoryStream(audioBytes))
                                    {
                                        using (var sp = new System.Media.SoundPlayer(ms))
                                        {
                                            sp.Play();
                                        }
                                    }
                                }
                                catch { }
                            };
                            activePlayer.Play();
                        }
                        catch
                        {
                            try
                            {
                                using (var ms = new System.IO.MemoryStream(audioBytes))
                                {
                                    using (var sp = new System.Media.SoundPlayer(ms))
                                    {
                                        sp.Play();
                                    }
                                }
                            }
                            catch { }
                        }
                    }));
                }
                catch { }
            });
        }

        public static void PlayWavBytes(byte[] wavBytes)
        {
            PlayAudioBytes(wavBytes, ".wav");
        }

        private static byte[] sendToneWav = null;
        private static byte[] receiveToneWav = null;

        // Генерация мягкого звука отправки в стиле Telegram (короткий нарастающий "свип")
        public static void PlaySendSound()
        {
            ThreadPool.QueueUserWorkItem(delegate
            {
                try
                {
                    if (sendToneWav == null)
                    {
                        sendToneWav = GenerateToneWav(850, 1350, 55, 0.12);
                    }
                    PlayWavBytes(sendToneWav);
                }
                catch { }
            });
        }

        // Генерация мягкого звука получения сообщения (двойной мелодичный колокольчик D5 -> D6)
        public static void PlayReceiveSound()
        {
            ThreadPool.QueueUserWorkItem(delegate
            {
                try
                {
                    if (receiveToneWav == null)
                    {
                        receiveToneWav = GenerateDoubleToneWav(587, 880, 1174, 180, 0.14);
                    }
                    PlayWavBytes(receiveToneWav);
                }
                catch { }
            });
        }

        private static byte[] GenerateToneWav(double startFreq, double endFreq, int durationMs, double volume)
        {
            int sampleRate = 44100;
            int numSamples = (int)(sampleRate * (durationMs / 1000.0));
            using (var ms = new MemoryStream())
            using (var writer = new BinaryWriter(ms))
            {
                writer.Write(new char[4] { 'R', 'I', 'F', 'F' });
                writer.Write(36 + numSamples * 2);
                writer.Write(new char[4] { 'W', 'A', 'V', 'E' });
                writer.Write(new char[4] { 'f', 'm', 't', ' ' });
                writer.Write(16);
                writer.Write((short)1); // PCM
                writer.Write((short)1); // Mono
                writer.Write(sampleRate);
                writer.Write(sampleRate * 2);
                writer.Write((short)2);
                writer.Write((short)16);
                writer.Write(new char[4] { 'd', 'a', 't', 'a' });
                writer.Write(numSamples * 2);

                for (int i = 0; i < numSamples; i++)
                {
                    double t = (double)i / numSamples;
                    double freq = startFreq + (endFreq - startFreq) * t;
                    double env = 1.0 - t; // Плавное затухание
                    short val = (short)(Math.Sin(2.0 * Math.PI * freq * (i / (double)sampleRate)) * 32767 * volume * env);
                    writer.Write(val);
                }
                writer.Flush();
                return ms.ToArray();
            }
        }

        private static byte[] GenerateDoubleToneWav(double f1, double f2, double f3, int durationMs, double volume)
        {
            int sampleRate = 44100;
            int numSamples = (int)(sampleRate * (durationMs / 1000.0));
            using (var ms = new MemoryStream())
            using (var writer = new BinaryWriter(ms))
            {
                writer.Write(new char[4] { 'R', 'I', 'F', 'F' });
                writer.Write(36 + numSamples * 2);
                writer.Write(new char[4] { 'W', 'A', 'V', 'E' });
                writer.Write(new char[4] { 'f', 'm', 't', ' ' });
                writer.Write(16);
                writer.Write((short)1); // PCM
                writer.Write((short)1); // Mono
                writer.Write(sampleRate);
                writer.Write(sampleRate * 2);
                writer.Write((short)2);
                writer.Write((short)16);
                writer.Write(new char[4] { 'd', 'a', 't', 'a' });
                writer.Write(numSamples * 2);

                int half = numSamples / 2;
                for (int i = 0; i < numSamples; i++)
                {
                    double t = (double)i / numSamples;
                    double env = Math.Exp(-3.5 * t);
                    double freq = (i < half) ? f1 : f3;
                    short val = (short)(Math.Sin(2.0 * Math.PI * freq * (i / (double)sampleRate)) * 32767 * volume * env);
                    writer.Write(val);
                }
                writer.Flush();
                return ms.ToArray();
            }
        }
    }

    // =========================================================================
    // МОДЕЛИ ДАННЫХ
    // =========================================================================
    public class ContactModel
    {
        public string Id { get; set; }
        public string Name { get; set; }
        public string PublicKeyB64 { get; set; }
        public string LastMessage { get; set; }
        public string LastTime { get; set; }
        public int UnreadCount { get; set; }
        public bool IsGroup { get; set; }
        public List<string> MemberIds { get; set; }
    }

    public class MessageModel
    {
        public string Id { get; set; }
        public bool FromMe { get; set; }
        public bool IsRead { get; set; }
        public bool IsEdited { get; set; }
        public string SenderId { get; set; }
        public string SenderName { get; set; }
        public string Text { get; set; }
        public string PhotoB64 { get; set; }
        public string VoiceB64 { get; set; }
        public int VoiceDuration { get; set; }
        public string FileName { get; set; }
        public long FileSize { get; set; }
        public string FileType { get; set; }
        public string FileB64 { get; set; }
        public long Timestamp { get; set; }
        public int DestructSeconds { get; set; }
        public string CipherDebug { get; set; }
        public string ReplyToId { get; set; }
        public string ReplyPreviewText { get; set; }
        public string ReplySenderName { get; set; }
        public Dictionary<string, List<string>> Reactions { get; set; }
        public string ForwardedFrom { get; set; }
    }

    // =========================================================================
    // ГЛАВНОЕ ОКНО CIPHER (100% ЧИСТЫЙ WPF DIRECTX БЕЗ БРАУЗЕРА)
    // =========================================================================
    public class MainWindow : Window
    {
        [DllImport("dwmapi.dll")]
        private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int attrValue, int attrSize);

        // Telegram Desktop Dark палитра
        private static readonly SolidColorBrush BrushBgMain = new SolidColorBrush(Color.FromRgb(14, 22, 33)); // #0E1621
        private static readonly SolidColorBrush BrushSidebar = new SolidColorBrush(Color.FromRgb(23, 33, 43)); // #17212B
        private static readonly SolidColorBrush BrushHeader = new SolidColorBrush(Color.FromRgb(23, 33, 43)); // #17212B
        private static readonly SolidColorBrush BrushInputArea = new SolidColorBrush(Color.FromRgb(23, 33, 43)); // #17212B
        private static readonly SolidColorBrush BrushInputBox = new SolidColorBrush(Color.FromRgb(36, 47, 61)); // #242F3D
        private static readonly SolidColorBrush BrushAccentTg = new SolidColorBrush(Color.FromRgb(82, 136, 193)); // #5288C1
        private static readonly SolidColorBrush BrushBubbleMe = new SolidColorBrush(Color.FromRgb(43, 82, 120)); // #2B5278
        private static readonly SolidColorBrush BrushBubbleOther = new SolidColorBrush(Color.FromRgb(24, 37, 51)); // #182533
        private static readonly SolidColorBrush BrushTextMuted = new SolidColorBrush(Color.FromRgb(127, 145, 164)); // #7F91A4
        private static readonly SolidColorBrush BrushBorderSubtle = new SolidColorBrush(Color.FromArgb(28, 255, 255, 255));

        private UserIdentity identity;
        private string userName;
        private ClientWebSocket webSocket;
        private CancellationTokenSource wsCts;
        private List<ContactModel> contacts = new List<ContactModel>();
        private Dictionary<string, List<MessageModel>> messages = new Dictionary<string, List<MessageModel>>();
        private ContactModel activeContact = null;
        private JavaScriptSerializer json = new JavaScriptSerializer { MaxJsonLength = int.MaxValue };
        private DispatcherTimer pairSyncTimer;
        private HashSet<string> onlineClientIds = new HashSet<string>();

        // UI Элементы
        private Grid rootGrid;
        private TextBlock txtStatus;
        private Ellipse dotStatus;
        private StackPanel panelContacts;
        private TextBlock serverText;
        private TextBlock myNameTxt;
        private TextBox txtSearch;
        private TextBlock txtSearchPlaceholder;
        private Grid chatAreaGrid;
        private TextBlock txtActiveName;
        private TextBlock txtActiveStatus;
        private Border activeAvatarContainer;
        private ScrollViewer scrollMessages;
        private StackPanel panelMessages;
        private Border emptyChatPlaceholder;
        private TextBox txtInput;
        private TextBlock txtInputPlaceholder;
        private Border attachmentPreviewBar;
        private TextBlock txtPreviewInfo;
        private Border voiceRecordingBar;
        private TextBlock txtVoiceTimer;
        private DispatcherTimer voiceTimer;
        private int voiceDurationSeconds = 0;
        private string attachedPhotoB64 = null;
        private string attachedPhotoName = null;
        private byte[] attachedFileBytes = null;
        private string attachedFileName = null;
        private long attachedFileSize = 0;
        private string attachedFileType = null;
        private int currentDestructSeconds = 0;
        private Border destructPill;
        private TextBlock txtDestructLabel;
        private MessageModel replyingMessage = null;
        private Border replyPreviewBar;
        private TextBlock txtReplyName;
        private TextBlock txtReplyContent;
        private MessageModel editingMessage = null;
        private Border editPreviewBar;
        private TextBlock txtEditContent;

        // Telegram функции (Реакции, Закрепленные сообщения, Поиск в чате, Черновики, Пересылка)
        private Dictionary<string, string> pinnedMessages = new Dictionary<string, string>();
        private Dictionary<string, string> chatDrafts = new Dictionary<string, string>();
        private HashSet<string> typingContacts = new HashSet<string>();
        private DispatcherTimer typingTimer = null;
        private Border pinnedBanner = null;
        private TextBlock txtPinnedSnippet = null;
        private Border inChatSearchBar = null;
        private TextBox txtInChatQuery = null;
        private TextBlock txtInChatCount = null;
        private List<string> inChatSearchResults = new List<string>();
        private int inChatSearchIndex = -1;
        private double currentAudioSpeed = 1.0;
        private long lastTypingSentMs = 0;

        // In-App уведомления и модальные окна (ВМЕСТО УРОДЛИВЫХ MESSAGEBOX)
        private Border toastCard;
        private TextBlock toastIconTxt;
        private TextBlock toastBodyTxt;
        private DispatcherTimer toastTimer;
        private Grid modalOverlayGrid;
        private Border modalDialogCard;
        private StackPanel modalContentStack;

        public MainWindow(string user)
        {
            this.userName = string.IsNullOrEmpty(user) ? "\u0410\u043B\u0438\u0441\u0430" : user;
            this.identity = NativeCrypto.LoadOrGenerateIdentity(this.userName);

            this.Title = "CIPHER — " + this.userName + " (Zero-Knowledge Desktop)";
            this.Width = 1180;
            this.Height = 780;
            this.MinWidth = 820;
            this.MinHeight = 560;
            this.WindowStartupLocation = WindowStartupLocation.CenterScreen;
            this.Background = BrushBgMain;
            this.Foreground = Brushes.White;
            this.FontFamily = new FontFamily("Segoe UI, -apple-system, sans-serif");

            string icoPath = System.IO.Path.Combine(Program.AppDir ?? "", "app.ico");
            if (File.Exists(icoPath))
            {
                try { this.Icon = BitmapFrame.Create(new Uri(icoPath)); } catch { }
            }

            BuildTelegramInterface();
            LoadPinnedMessages();

            LoadContacts();
            SetupMutualPairing();

            ConnectWebSocketAsync();

            this.Loaded += delegate { ApplyNativeDarkTitleBar(); };

            // Фоновый таймер синхронизации сопряжения (когда открыто Окно 2)
            pairSyncTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(1500) };
            pairSyncTimer.Tick += delegate { SetupMutualPairing(); };
            pairSyncTimer.Start();
        }

        private void ApplyNativeDarkTitleBar()
        {
            try
            {
                var helper = new System.Windows.Interop.WindowInteropHelper(this);
                int darkMode = 1;
                DwmSetWindowAttribute(helper.Handle, 19, ref darkMode, sizeof(int));
                DwmSetWindowAttribute(helper.Handle, 20, ref darkMode, sizeof(int));
            }
            catch { }
        }

        // =====================================================================
        // КАСТОМНЫЕ IN-APP УВЕДОМЛЕНИЯ И МОДАЛКИ (БЕЗ MESSAGEBOX)
        // =====================================================================
        public void ShowToast(string message, ToastType type)
        {
            Dispatcher.Invoke(new Action(delegate
            {
                toastBodyTxt.Text = message;
                Color accentCol;
                string icon;
                switch (type)
                {
                    case ToastType.Success:
                        accentCol = Color.FromRgb(16, 185, 129); // #10B981
                        icon = "✓";
                        break;
                    case ToastType.Warning:
                        accentCol = Color.FromRgb(245, 158, 11); // #F59E0B
                        icon = "⚠";
                        break;
                    case ToastType.Error:
                        accentCol = Color.FromRgb(244, 63, 94); // #F43F5E
                        icon = "✕";
                        break;
                    default:
                        accentCol = Color.FromRgb(56, 189, 248); // #38BDF8
                        icon = "ℹ";
                        break;
                }

                toastIconTxt.Text = icon;
                toastIconTxt.Foreground = new SolidColorBrush(accentCol);
                toastCard.BorderBrush = new SolidColorBrush(accentCol);

                toastCard.Visibility = Visibility.Visible;
                var anim = new DoubleAnimation(0.0, 1.0, new Duration(TimeSpan.FromMilliseconds(180)));
                toastCard.BeginAnimation(UIElement.OpacityProperty, anim);

                if (toastTimer == null)
                {
                    toastTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(3200) };
                    toastTimer.Tick += delegate
                    {
                        toastTimer.Stop();
                        HideToast();
                    };
                }
                toastTimer.Stop();
                toastTimer.Start();
            }));
        }

        public void ShowToast(string message)
        {
            ShowToast(message, ToastType.Info);
        }

        private void HideToast()
        {
            var anim = new DoubleAnimation(1.0, 0.0, new Duration(TimeSpan.FromMilliseconds(200)));
            anim.Completed += delegate { toastCard.Visibility = Visibility.Collapsed; };
            toastCard.BeginAnimation(UIElement.OpacityProperty, anim);
        }

        private void ShowModal(UIElement content)
        {
            modalContentStack.Children.Clear();
            modalContentStack.Children.Add(content);
            modalOverlayGrid.Visibility = Visibility.Visible;
        }

        private void HideModal()
        {
            modalOverlayGrid.Visibility = Visibility.Collapsed;
            modalContentStack.Children.Clear();
        }

        private void ShowConfirmDialog(string title, string message, string confirmBtnText, Action onConfirm, bool isDestructive)
        {
            var panel = new StackPanel { Width = 380, Margin = new Thickness(24) };

            var titleTxt = new TextBlock
            {
                Text = title,
                Foreground = Brushes.White,
                FontSize = 15.5,
                FontWeight = FontWeights.Bold,
                Margin = new Thickness(0, 0, 0, 10)
            };
            var msgTxt = new TextBlock
            {
                Text = message,
                Foreground = BrushTextMuted,
                FontSize = 13,
                TextWrapping = TextWrapping.Wrap,
                LineHeight = 18,
                Margin = new Thickness(0, 0, 0, 22)
            };

            var btnRow = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                HorizontalAlignment = HorizontalAlignment.Right
            };

            var btnCancel = CreateTgButton("Отмена", Color.FromArgb(25, 255, 255, 255), Color.FromArgb(45, 255, 255, 255), delegate
            {
                HideModal();
            });
            btnCancel.Margin = new Thickness(0, 0, 10, 0);

            Color btnCol = isDestructive ? Color.FromRgb(225, 29, 72) : Color.FromRgb(43, 82, 120);
            Color btnHover = isDestructive ? Color.FromRgb(244, 63, 94) : Color.FromRgb(58, 107, 153);

            var btnConfirm = CreateTgButton(confirmBtnText, btnCol, btnHover, delegate
            {
                HideModal();
                if (onConfirm != null) onConfirm();
            });

            btnRow.Children.Add(btnCancel);
            btnRow.Children.Add(btnConfirm);

            panel.Children.Add(titleTxt);
            panel.Children.Add(msgTxt);
            panel.Children.Add(btnRow);

            ShowModal(panel);
        }

        private void ShowAddContactModal()
        {
            var panel = new StackPanel { Width = 430, Margin = new Thickness(24) };

            var headerRow = new DockPanel { Margin = new Thickness(0, 0, 0, 16) };
            var titleTxt = new TextBlock
            {
                Text = "Добавить контакт",
                Foreground = Brushes.White,
                FontSize = 16,
                FontWeight = FontWeights.Bold,
                VerticalAlignment = VerticalAlignment.Center
            };
            var btnClose = CreateTgIconButton("✕", 13, Colors.Transparent, Color.FromArgb(40, 255, 255, 255), delegate
            {
                HideModal();
            });
            btnClose.HorizontalAlignment = HorizontalAlignment.Right;
            headerRow.Children.Add(titleTxt);
            headerRow.Children.Add(btnClose);
            panel.Children.Add(headerRow);

            panel.Children.Add(new TextBlock { Text = "Имя контакта:", Foreground = BrushTextMuted, FontSize = 12, Margin = new Thickness(0, 0, 0, 6) });
            var txtName = new TextBox
            {
                Background = BrushInputBox,
                Foreground = Brushes.White,
                Padding = new Thickness(10, 8, 10, 8),
                FontSize = 13,
                BorderThickness = new Thickness(1),
                BorderBrush = BrushBorderSubtle
            };
            panel.Children.Add(txtName);

            panel.Children.Add(new TextBlock { Text = "Открытый ключ собеседника (Base64):", Foreground = BrushTextMuted, FontSize = 12, Margin = new Thickness(0, 14, 0, 6) });
            var txtKey = new TextBox
            {
                Background = BrushInputBox,
                Foreground = Brushes.White,
                Padding = new Thickness(10, 8, 10, 8),
                FontSize = 11,
                Height = 72,
                TextWrapping = TextWrapping.Wrap,
                AcceptsReturn = true,
                BorderThickness = new Thickness(1),
                BorderBrush = BrushBorderSubtle
            };
            panel.Children.Add(txtKey);

            var btnAdd = CreateTgButton("Добавить в контакты", Color.FromRgb(43, 82, 120), Color.FromRgb(58, 107, 153), delegate
            {
                string name = txtName.Text.Trim();
                string key = txtKey.Text.Trim();
                if (string.IsNullOrEmpty(name) || string.IsNullOrEmpty(key))
                {
                    ShowToast("Пожалуйста, заполните имя и ключ", ToastType.Warning);
                    return;
                }

                try
                {
                    byte[] pub = Convert.FromBase64String(key);
                    string idHex;
                    using (var sha = SHA256.Create())
                    {
                        byte[] hash = sha.ComputeHash(pub);
                        var sb = new StringBuilder();
                        foreach (byte b in hash) sb.Append(b.ToString("x2"));
                        idHex = sb.ToString();
                    }

                    var newC = new ContactModel
                    {
                        Id = idHex,
                        Name = name,
                        PublicKeyB64 = key,
                        LastMessage = "Чат защищен E2EE",
                        LastTime = DateTime.Now.ToString("HH:mm")
                    };
                    contacts.Add(newC);
                    SaveContacts();
                    HideModal();
                    SelectContact(newC);
                    ShowToast("Контакт '" + name + "' добавлен", ToastType.Success);
                }
                catch (Exception ex)
                {
                    ShowToast("Некорректный ключ: " + ex.Message, ToastType.Error);
                }
            });
            btnAdd.Margin = new Thickness(0, 20, 0, 0);
            btnAdd.Height = 36;
            panel.Children.Add(btnAdd);

            ShowModal(panel);
            txtName.Focus();
        }

        private void ShowCreateGroupModal()
        {
            var panel = new StackPanel { Width = 440, Margin = new Thickness(24) };

            var headerRow = new DockPanel { Margin = new Thickness(0, 0, 0, 16) };
            var titleTxt = new TextBlock
            {
                Text = "Создать групповой чат",
                Foreground = Brushes.White,
                FontSize = 16,
                FontWeight = FontWeights.Bold,
                VerticalAlignment = VerticalAlignment.Center
            };
            var btnClose = CreateTgIconButton("✕", 13, Colors.Transparent, Color.FromArgb(40, 255, 255, 255), delegate
            {
                HideModal();
            });
            btnClose.HorizontalAlignment = HorizontalAlignment.Right;
            headerRow.Children.Add(titleTxt);
            headerRow.Children.Add(btnClose);
            panel.Children.Add(headerRow);

            panel.Children.Add(new TextBlock { Text = "Название группы:", Foreground = BrushTextMuted, FontSize = 12, Margin = new Thickness(0, 0, 0, 6) });
            var txtGroupName = new TextBox
            {
                Background = BrushInputBox,
                Foreground = Brushes.White,
                Padding = new Thickness(10, 8, 10, 8),
                FontSize = 13,
                BorderThickness = new Thickness(1),
                BorderBrush = BrushBorderSubtle
            };
            panel.Children.Add(txtGroupName);

            panel.Children.Add(new TextBlock { Text = "Выберите участников группы:", Foreground = BrushTextMuted, FontSize = 12, Margin = new Thickness(0, 14, 0, 6) });

            var contactsScroll = new ScrollViewer
            {
                MaxHeight = 180,
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                Background = BrushInputBox,
                Padding = new Thickness(10)
            };
            var contactsStack = new StackPanel();
            var checkBoxes = new List<CheckBox>();

            foreach (var c in contacts)
            {
                if (c.IsGroup) continue;
                var cb = new CheckBox
                {
                    Content = c.Name + " (" + (c.Id.Length > 8 ? c.Id.Substring(0, 8) + "..." : c.Id) + ")",
                    Foreground = Brushes.White,
                    FontSize = 12.5,
                    Margin = new Thickness(0, 4, 0, 4),
                    Tag = c.Id
                };
                checkBoxes.Add(cb);
                contactsStack.Children.Add(cb);
            }

            if (checkBoxes.Count == 0)
            {
                contactsStack.Children.Add(new TextBlock
                {
                    Text = "Нет доступных контактов. Сначала добавьте контакты.",
                    Foreground = BrushTextMuted,
                    FontSize = 12
                });
            }

            contactsScroll.Content = contactsStack;
            panel.Children.Add(contactsScroll);

            var btnCreate = CreateTgButton("Создать группу", Color.FromRgb(43, 82, 120), Color.FromRgb(58, 107, 153), delegate
            {
                string gName = txtGroupName.Text.Trim();
                if (string.IsNullOrEmpty(gName))
                {
                    ShowToast("Введите название группы", ToastType.Warning);
                    return;
                }

                var selectedIds = new List<string>();
                selectedIds.Add(identity.Id);
                foreach (var cb in checkBoxes)
                {
                    if (cb.IsChecked == true && cb.Tag != null)
                    {
                        selectedIds.Add(cb.Tag.ToString());
                    }
                }

                if (selectedIds.Count < 2)
                {
                    ShowToast("Выберите хотя бы одного участника", ToastType.Warning);
                    return;
                }

                string gId = "grp_" + DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() + "_" + Guid.NewGuid().ToString("N").Substring(0, 6);
                var newGrp = new ContactModel
                {
                    Id = gId,
                    Name = gName,
                    IsGroup = true,
                    MemberIds = selectedIds,
                    PublicKeyB64 = "",
                    LastMessage = "Групповой чат создан",
                    LastTime = DateTime.Now.ToString("HH:mm")
                };

                contacts.Add(newGrp);
                SaveContacts();
                HideModal();
                SelectContact(newGrp);
                ShowToast("Группа '" + gName + "' создана (" + selectedIds.Count + " участников)", ToastType.Success);
            });
            btnCreate.Margin = new Thickness(0, 20, 0, 0);
            btnCreate.Height = 36;
            panel.Children.Add(btnCreate);

            ShowModal(panel);
            txtGroupName.Focus();
        }

        private void ShowContactKeyInfo()
        {
            if (activeContact == null) return;

            var panel = new StackPanel { Width = 480, Margin = new Thickness(24) };

            var headerRow = new DockPanel { Margin = new Thickness(0, 0, 0, 16) };
            var titleTxt = new TextBlock
            {
                Text = "Профиль — " + activeContact.Name,
                Foreground = Brushes.White,
                FontSize = 16,
                FontWeight = FontWeights.Bold,
                VerticalAlignment = VerticalAlignment.Center
            };
            var btnClose = CreateTgIconButton("✕", 13, Colors.Transparent, Color.FromArgb(40, 255, 255, 255), delegate
            {
                HideModal();
            });
            btnClose.HorizontalAlignment = HorizontalAlignment.Right;
            headerRow.Children.Add(titleTxt);
            headerRow.Children.Add(btnClose);
            panel.Children.Add(headerRow);

            panel.Children.Add(new TextBlock { Text = "ID собеседника (SHA-256):", Foreground = BrushTextMuted, FontSize = 12, Margin = new Thickness(0, 0, 0, 4) });
            var tId = new TextBox
            {
                Text = activeContact.Id,
                IsReadOnly = true,
                Background = BrushInputBox,
                Foreground = Brushes.White,
                Padding = new Thickness(8),
                FontSize = 11.5,
                Margin = new Thickness(0, 0, 0, 14),
                BorderThickness = new Thickness(1),
                BorderBrush = BrushBorderSubtle
            };
            panel.Children.Add(tId);

            panel.Children.Add(new TextBlock { Text = "Открытый ключ (P-256 ECDH):", Foreground = BrushTextMuted, FontSize = 12, Margin = new Thickness(0, 0, 0, 4) });
            var tKey = new TextBox
            {
                Text = activeContact.PublicKeyB64,
                IsReadOnly = true,
                Background = BrushInputBox,
                Foreground = Brushes.White,
                Padding = new Thickness(8),
                FontSize = 11,
                Height = 72,
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 0, 0, 18),
                BorderThickness = new Thickness(1),
                BorderBrush = BrushBorderSubtle
            };
            panel.Children.Add(tKey);

            var btnClear = CreateTgButton("🧹 Очистить историю сообщений", Color.FromRgb(51, 65, 85), Color.FromRgb(71, 85, 105), delegate
            {
                ShowConfirmDialog("Очистить историю?", "Все сообщения в переписке с " + activeContact.Name + " будут удалены.", "Очистить", delegate
                {
                    string cId = activeContact.Id;
                    if (messages.ContainsKey(cId)) messages[cId].Clear();
                    if (pinnedMessages.ContainsKey(cId)) pinnedMessages.Remove(cId);
                    if (chatDrafts.ContainsKey(cId)) chatDrafts.Remove(cId);
                    SaveMessages();
                    SavePinnedMessages();
                    panelMessages.Children.Clear();
                    emptyChatPlaceholder.Visibility = Visibility.Visible;
                    if (pinnedBanner != null) pinnedBanner.Visibility = Visibility.Collapsed;
                    RenderContactList();
                    HideModal();
                    ShowToast("История чата очищена", ToastType.Info);
                }, false);
            });
            btnClear.Height = 36;
            btnClear.Margin = new Thickness(0, 0, 0, 10);
            panel.Children.Add(btnClear);

            var btnDel = CreateTgButton("🗑 Удалить чат и историю", Color.FromRgb(225, 29, 72), Color.FromRgb(244, 63, 94), delegate
            {
                ShowConfirmDialog("Удалить диалог?", "Вся переписка с " + activeContact.Name + " будет удалена безвозвратно.", "Удалить", delegate
                {
                    string removedId = activeContact.Id;
                    contacts.Remove(activeContact);
                    if (messages.ContainsKey(removedId)) messages.Remove(removedId);
                    SaveContacts();
                    activeContact = null;
                    txtActiveName.Text = "Выберите чат";
                    txtActiveStatus.Text = "Сквозной шифр активен";
                    activeAvatarContainer.Child = null;
                    panelMessages.Children.Clear();
                    emptyChatPlaceholder.Visibility = Visibility.Visible;
                    RenderContactList();
                    HideModal();
                    ShowToast("Чат удален", ToastType.Info);
                }, true);
            });
            btnDel.Height = 36;
            panel.Children.Add(btnDel);

            ShowModal(panel);
        }

        private void ShowPhotoViewerModal(BitmapImage img)
        {
            var panel = new Grid { Width = 720, Height = 520, Margin = new Thickness(16) };
            var imgCtrl = new Image { Source = img, Stretch = Stretch.Uniform };
            var btnClose = CreateTgIconButton("✕", 14, Color.FromArgb(160, 0, 0, 0), Color.FromArgb(220, 0, 0, 0), delegate
            {
                HideModal();
            });
            btnClose.HorizontalAlignment = HorizontalAlignment.Right;
            btnClose.VerticalAlignment = VerticalAlignment.Top;
            btnClose.Margin = new Thickness(10);

            var btnSave = CreateTgButton("💾 Сохранить фото", Color.FromArgb(180, 20, 30, 45), Color.FromArgb(230, 30, 45, 65), delegate
            {
                try
                {
                    var sfd = new Microsoft.Win32.SaveFileDialog
                    {
                        Filter = "JPEG Image (*.jpg)|*.jpg|PNG Image (*.png)|*.png",
                        FileName = "photo_" + DateTime.Now.ToString("yyyyMMdd_HHmmss") + ".jpg"
                    };
                    if (sfd.ShowDialog() == true)
                    {
                        var enc = new JpegBitmapEncoder();
                        enc.Frames.Add(BitmapFrame.Create(img));
                        using (var fs = new FileStream(sfd.FileName, FileMode.Create))
                        {
                            enc.Save(fs);
                        }
                        ShowToast("Фотография сохранена", ToastType.Success);
                    }
                }
                catch (Exception ex)
                {
                    ShowToast("Ошибка сохранения: " + ex.Message, ToastType.Error);
                }
            });
            btnSave.HorizontalAlignment = HorizontalAlignment.Left;
            btnSave.VerticalAlignment = VerticalAlignment.Bottom;
            btnSave.Margin = new Thickness(10);
            btnSave.Height = 34;

            panel.Children.Add(imgCtrl);
            panel.Children.Add(btnClose);
            panel.Children.Add(btnSave);
            ShowModal(panel);
        }

        public static string FormatBytes(long bytes)
        {
            if (bytes < 1024) return bytes + " B";
            if (bytes < 1024 * 1024) return (bytes / 1024.0).ToString("0.#") + " KB";
            return (bytes / (1024.0 * 1024.0)).ToString("0.#") + " MB";
        }

        private void SaveCurrentIdentity()
        {
            try
            {
                string appData = System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "CipherNative");
                string idFile = System.IO.Path.Combine(appData, "identity_p256_" + this.userName + ".json");
                File.WriteAllText(idFile, json.Serialize(identity), Encoding.UTF8);
            }
            catch { }
        }

        private void UpdateServerFooterText()
        {
            if (serverText != null)
            {
                string displayAddr = "127.0.0.1:8080";
                try
                {
                    string u = !string.IsNullOrEmpty(identity.ServerUrl) ? identity.ServerUrl : "wss://fotowaqu.ru";
                    var uri = new Uri(u);
                    displayAddr = uri.Authority;
                }
                catch { }
                serverText.Text = "Слепой релей: " + displayAddr + " 🔒";
            }
        }

        private void ShowProfileModal()
        {
            var panel = new StackPanel { Width = 480, Margin = new Thickness(24) };

            var header = new TextBlock
            {
                Text = "👤 Мой суверенный профиль",
                Foreground = Brushes.White,
                FontSize = 18,
                FontWeight = FontWeights.Bold,
                Margin = new Thickness(0, 0, 0, 16)
            };
            panel.Children.Add(header);

            var avRow = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 18) };
            avRow.Children.Add(CreateAvatarCircle(identity.Name, identity.Id, 54));
            var avInfo = new StackPanel { Margin = new Thickness(14, 0, 0, 0), VerticalAlignment = VerticalAlignment.Center };
            var chip = new Border
            {
                Background = new SolidColorBrush(Color.FromArgb(30, 6, 182, 212)),
                CornerRadius = new CornerRadius(4),
                Padding = new Thickness(6, 2, 6, 2),
                HorizontalAlignment = HorizontalAlignment.Left
            };
            chip.Child = new TextBlock { Text = "NIST P-256 ECDH • AES-256-GCM", Foreground = new SolidColorBrush(Color.FromRgb(6, 182, 212)), FontSize = 10, FontWeight = FontWeights.Bold };
            avInfo.Children.Add(chip);
            avRow.Children.Add(avInfo);
            panel.Children.Add(avRow);

            panel.Children.Add(new TextBlock { Text = "Отображаемое имя:", Foreground = BrushTextMuted, FontSize = 12, Margin = new Thickness(0, 0, 0, 4) });
            var nameDock = new DockPanel { Margin = new Thickness(0, 0, 0, 14) };
            var txtEditName = new TextBox
            {
                Text = identity.Name,
                Background = BrushInputBox,
                Foreground = Brushes.White,
                Padding = new Thickness(8),
                FontSize = 13,
                BorderThickness = new Thickness(1),
                BorderBrush = BrushBorderSubtle
            };
            var btnSaveName = CreateTgButton("Сохранить", Color.FromRgb(43, 82, 120), Color.FromRgb(58, 107, 153), delegate
            {
                string newN = txtEditName.Text.Trim();
                if (!string.IsNullOrEmpty(newN))
                {
                    identity.Name = newN;
                    this.userName = newN;
                    this.Title = "CIPHER — " + this.userName + " (Zero-Knowledge Desktop)";
                    if (myNameTxt != null) myNameTxt.Text = newN;
                    SaveCurrentIdentity();
                    ShowToast("Имя профиля обновлено: " + newN, ToastType.Success);
                }
            });
            btnSaveName.Width = 90;
            btnSaveName.Height = 32;
            btnSaveName.Margin = new Thickness(8, 0, 0, 0);
            DockPanel.SetDock(btnSaveName, Dock.Right);
            nameDock.Children.Add(btnSaveName);
            nameDock.Children.Add(txtEditName);
            panel.Children.Add(nameDock);

            panel.Children.Add(new TextBlock { Text = "Ваш постоянный E2EE ID (SHA-256):", Foreground = BrushTextMuted, FontSize = 12, Margin = new Thickness(0, 0, 0, 4) });
            var idDock = new DockPanel { Margin = new Thickness(0, 0, 0, 14) };
            var txtId = new TextBox
            {
                Text = identity.Id,
                IsReadOnly = true,
                Background = BrushInputBox,
                Foreground = Brushes.White,
                Padding = new Thickness(8),
                FontSize = 11,
                BorderThickness = new Thickness(1),
                BorderBrush = BrushBorderSubtle
            };
            var btnCopyId = CreateTgButton("Копировать", Color.FromArgb(40, 255, 255, 255), Color.FromArgb(70, 255, 255, 255), delegate
            {
                Clipboard.SetText(identity.Id);
                ShowToast("ID скопирован в буфер", ToastType.Info);
            });
            btnCopyId.Width = 90;
            btnCopyId.Height = 32;
            btnCopyId.Margin = new Thickness(8, 0, 0, 0);
            DockPanel.SetDock(btnCopyId, Dock.Right);
            idDock.Children.Add(btnCopyId);
            idDock.Children.Add(txtId);
            panel.Children.Add(idDock);

            panel.Children.Add(new TextBlock { Text = "Открытый ключ (Base64):", Foreground = BrushTextMuted, FontSize = 12, Margin = new Thickness(0, 0, 0, 4) });
            var keyDock = new DockPanel { Margin = new Thickness(0, 0, 0, 18) };
            var txtKey = new TextBox
            {
                Text = identity.PublicKeyB64,
                IsReadOnly = true,
                Background = BrushInputBox,
                Foreground = Brushes.White,
                Padding = new Thickness(8),
                FontSize = 11,
                Height = 56,
                TextWrapping = TextWrapping.Wrap,
                BorderThickness = new Thickness(1),
                BorderBrush = BrushBorderSubtle
            };
            var btnCopyKey = CreateTgButton("Копировать", Color.FromArgb(40, 255, 255, 255), Color.FromArgb(70, 255, 255, 255), delegate
            {
                Clipboard.SetText(identity.PublicKeyB64);
                ShowToast("Открытый ключ скопирован в буфер", ToastType.Success);
            });
            btnCopyKey.Width = 90;
            btnCopyKey.Height = 32;
            btnCopyKey.Margin = new Thickness(8, 0, 0, 0);
            DockPanel.SetDock(btnCopyKey, Dock.Right);
            keyDock.Children.Add(btnCopyKey);
            keyDock.Children.Add(txtKey);
            panel.Children.Add(keyDock);

            var backupGrid = new System.Windows.Controls.Primitives.UniformGrid { Columns = 2, Margin = new Thickness(0, 0, 0, 16) };
            var btnExport = CreateTgButton("📤 Экспорт ключей (.json)", Color.FromRgb(43, 82, 120), Color.FromRgb(58, 107, 153), delegate
            {
                var sfd = new Microsoft.Win32.SaveFileDialog
                {
                    Filter = "JSON Identity (*.json)|*.json",
                    FileName = "cipher_backup_" + identity.Name + ".json",
                    Title = "Сохранить резервную копию ключей"
                };
                if (sfd.ShowDialog() == true)
                {
                    try
                    {
                        File.WriteAllText(sfd.FileName, json.Serialize(identity), Encoding.UTF8);
                        ShowToast("Резервная копия ключей экспортирована!", ToastType.Success);
                    }
                    catch (Exception ex)
                    {
                        ShowToast("Ошибка экспорта: " + ex.Message, ToastType.Error);
                    }
                }
            });
            btnExport.Height = 34;
            btnExport.Margin = new Thickness(0, 0, 6, 0);

            var btnImport = CreateTgButton("📥 Импорт ключей (.json)", Color.FromArgb(40, 255, 255, 255), Color.FromArgb(70, 255, 255, 255), delegate
            {
                var ofd = new Microsoft.Win32.OpenFileDialog
                {
                    Filter = "JSON Identity (*.json)|*.json",
                    Title = "Выберите файл резервной копии ключей"
                };
                if (ofd.ShowDialog() == true)
                {
                    try
                    {
                        var imported = json.Deserialize<UserIdentity>(File.ReadAllText(ofd.FileName, Encoding.UTF8));
                        if (imported != null && !string.IsNullOrEmpty(imported.PublicKeyB64) && !string.IsNullOrEmpty(imported.PrivateKeyB64))
                        {
                            identity = imported;
                            this.userName = imported.Name;
                            this.Title = "CIPHER — " + this.userName + " (Zero-Knowledge Desktop)";
                            if (myNameTxt != null) myNameTxt.Text = imported.Name;
                            SaveCurrentIdentity();
                            ConnectWebSocketAsync();
                            HideModal();
                            ShowToast("Ключи успешно импортированы!", ToastType.Success);
                        }
                        else
                        {
                            ShowToast("Некорректный файл ключей", ToastType.Error);
                        }
                    }
                    catch (Exception ex)
                    {
                        ShowToast("Ошибка импорта: " + ex.Message, ToastType.Error);
                    }
                }
            });
            btnImport.Height = 34;
            btnImport.Margin = new Thickness(6, 0, 0, 0);

            backupGrid.Children.Add(btnExport);
            backupGrid.Children.Add(btnImport);
            panel.Children.Add(backupGrid);

            var btnShowQr = CreateTgButton("📱 Показать мой QR-код", Color.FromRgb(99, 102, 241), Color.FromRgb(79, 70, 229), delegate
            {
                ShowMyQrModal();
            });
            btnShowQr.Height = 34;
            btnShowQr.Margin = new Thickness(0, 0, 0, 10);
            panel.Children.Add(btnShowQr);

            var btnClose = CreateTgButton("Закрыть", Color.FromArgb(25, 255, 255, 255), Color.FromArgb(50, 255, 255, 255), delegate
            {
                HideModal();
            });
            btnClose.Height = 34;
            panel.Children.Add(btnClose);

            ShowModal(panel);
        }

        private void ShowMyQrModal()
        {
            var panel = new StackPanel { Width = 360, Margin = new Thickness(20), HorizontalAlignment = HorizontalAlignment.Center };
            panel.Children.Add(new TextBlock
            {
                Text = "📱 Мой QR-код",
                Foreground = Brushes.White,
                FontSize = 18,
                FontWeight = FontWeights.Bold,
                HorizontalAlignment = HorizontalAlignment.Center,
                Margin = new Thickness(0, 0, 0, 6)
            });
            panel.Children.Add(new TextBlock
            {
                Text = "Отсканируйте камерой мобильного приложения",
                Foreground = BrushTextMuted,
                FontSize = 12,
                HorizontalAlignment = HorizontalAlignment.Center,
                Margin = new Thickness(0, 0, 0, 16)
            });

            string qrPayload = json.Serialize(new
            {
                name = identity.Name,
                pub = identity.PublicKeyB64,
                id = identity.Id
            });

            var wb = new WebBrowser
            {
                Width = 240,
                Height = 240,
                HorizontalAlignment = HorizontalAlignment.Center
            };

            string qrJsPath = System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "public", "qrcode.js");
            string qrJs = File.Exists(qrJsPath) ? File.ReadAllText(qrJsPath) : "";

            string escapedData = qrPayload.Replace("\\", "\\\\").Replace("'", "\\'").Replace("\r", "").Replace("\n", "");
            string html = @"<!DOCTYPE html>
<html>
<head>
<meta http-equiv='X-UA-Compatible' content='IE=edge'>
<style>
* { margin:0; padding:0; box-sizing:border-box; }
body { background:#ffffff; display:flex; align-items:center; justify-content:center; height:100vh; overflow:hidden; }
#wrap { padding:10px; display:inline-block; }
img { display:block; }
</style>
</head>
<body>
<div id='wrap'><div id='qr'>Генерация...</div></div>
<script>
" + qrJs + @"
window.onload = function() {
    try {
        var qr = qrcode(0, 'M');
        qr.addData('" + escapedData + @"');
        qr.make();
        document.getElementById('qr').innerHTML = qr.createImgTag(4, 4);
    } catch(e) {
        document.getElementById('qr').innerHTML = '<span style=""color:red;font-size:11px;"">' + e.message + '</span>';
    }
};
</script>
</body>
</html>";

            wb.NavigateToString(html);

            var qrBorder = new Border
            {
                Background = Brushes.White,
                CornerRadius = new CornerRadius(14),
                Padding = new Thickness(10),
                HorizontalAlignment = HorizontalAlignment.Center,
                Child = wb
            };
            panel.Children.Add(qrBorder);

            var btnClose = CreateTgButton("Закрыть", Color.FromArgb(40, 255, 255, 255), Color.FromArgb(70, 255, 255, 255), delegate
            {
                HideModal();
            });
            btnClose.Height = 34;
            btnClose.Margin = new Thickness(0, 16, 0, 0);
            panel.Children.Add(btnClose);

            ShowModal(panel);
        }

        private void ShowServerSettingsModal()
        {
            var panel = new StackPanel { Width = 500, Margin = new Thickness(24) };

            var header = new TextBlock
            {
                Text = "⚙️ Подключение к слепому релею",
                Foreground = Brushes.White,
                FontSize = 17,
                FontWeight = FontWeights.Bold,
                Margin = new Thickness(0, 0, 0, 10)
            };
            panel.Children.Add(header);

            var infoTxt = new TextBlock
            {
                Text = "Для общения между двумя разными ПК через Интернет укажите публичный адрес сервера (например, туннель Cloudflare wss://...trycloudflare.com или ваш VPS).",
                Foreground = BrushTextMuted,
                FontSize = 12,
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 0, 0, 16),
                LineHeight = 17
            };
            panel.Children.Add(infoTxt);

            panel.Children.Add(new TextBlock { Text = "Адрес релей-сервера (ws:// или wss://):", Foreground = Brushes.White, FontSize = 12, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 0, 0, 4) });
            var txtUrl = new TextBox
            {
                Text = !string.IsNullOrEmpty(identity.ServerUrl) ? identity.ServerUrl : "wss://fotowaqu.ru",
                Background = BrushInputBox,
                Foreground = Brushes.White,
                Padding = new Thickness(8),
                FontSize = 13,
                Margin = new Thickness(0, 0, 0, 12),
                BorderThickness = new Thickness(1),
                BorderBrush = BrushBorderSubtle
            };
            panel.Children.Add(txtUrl);

            panel.Children.Add(new TextBlock { Text = "Пароль сервера (CIPHER_SERVER_SECRET, если задан):", Foreground = Brushes.White, FontSize = 12, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 0, 0, 4) });
            var txtSecret = new TextBox
            {
                Text = identity.ServerSecret ?? "",
                Background = BrushInputBox,
                Foreground = Brushes.White,
                Padding = new Thickness(8),
                FontSize = 13,
                Margin = new Thickness(0, 0, 0, 16),
                BorderThickness = new Thickness(1),
                BorderBrush = BrushBorderSubtle
            };
            panel.Children.Add(txtSecret);

            // Блок обнаруженного Cloudflare туннеля
            var tunnelBox = new Border
            {
                Background = new SolidColorBrush(Color.FromArgb(30, 82, 136, 193)),
                BorderBrush = new SolidColorBrush(Color.FromArgb(60, 82, 136, 193)),
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(8),
                Padding = new Thickness(12),
                Margin = new Thickness(0, 0, 0, 16),
                Visibility = Visibility.Collapsed
            };
            var tunnelStack = new StackPanel();
            var tunnelTitle = new TextBlock
            {
                Text = "🌐 Обнаружен публичный Cloudflare Tunnel:",
                Foreground = new SolidColorBrush(Color.FromRgb(107, 161, 219)),
                FontSize = 11.5,
                FontWeight = FontWeights.Bold,
                Margin = new Thickness(0, 0, 0, 4)
            };
            var tunnelValTxt = new TextBlock
            {
                Text = "",
                Foreground = Brushes.White,
                FontSize = 12,
                FontFamily = new FontFamily("Consolas, Courier New"),
                Margin = new Thickness(0, 0, 0, 8)
            };
            var tunnelBtnRow = new StackPanel { Orientation = Orientation.Horizontal };
            var btnCopyTunnel = CreateTgButton("📋 Скопировать для друга", Color.FromRgb(43, 82, 120), Color.FromRgb(58, 107, 153), delegate
            {
                Clipboard.SetText(tunnelValTxt.Text);
                ShowToast("Адрес туннеля скопирован в буфер!", ToastType.Success);
            });
            btnCopyTunnel.Height = 28;
            btnCopyTunnel.Padding = new Thickness(10, 0, 10, 0);

            var btnUseTunnel = CreateTgButton("Вставить в поле", Color.FromArgb(40, 255, 255, 255), Color.FromArgb(70, 255, 255, 255), delegate
            {
                txtUrl.Text = tunnelValTxt.Text;
            });
            btnUseTunnel.Height = 28;
            btnUseTunnel.Padding = new Thickness(10, 0, 10, 0);
            btnUseTunnel.Margin = new Thickness(8, 0, 0, 0);

            tunnelBtnRow.Children.Add(btnCopyTunnel);
            tunnelBtnRow.Children.Add(btnUseTunnel);
            tunnelStack.Children.Add(tunnelTitle);
            tunnelStack.Children.Add(tunnelValTxt);
            tunnelStack.Children.Add(tunnelBtnRow);
            tunnelBox.Child = tunnelStack;
            panel.Children.Add(tunnelBox);

            ThreadPool.QueueUserWorkItem(delegate
            {
                try
                {
                    using (var wc = new System.Net.WebClient { Encoding = Encoding.UTF8 })
                    {
                        string infoJson = wc.DownloadString("http://127.0.0.1:8080/api/server-info");
                        var info = json.Deserialize<Dictionary<string, object>>(infoJson);
                        if (info != null && info.ContainsKey("tunnelUrl") && info["tunnelUrl"] != null)
                        {
                            string tUrl = info["tunnelUrl"].ToString();
                            if (!string.IsNullOrEmpty(tUrl))
                            {
                                Dispatcher.Invoke(new Action(delegate
                                {
                                    tunnelValTxt.Text = tUrl;
                                    tunnelBox.Visibility = Visibility.Visible;
                                }));
                            }
                        }
                    }
                }
                catch { }
            });

            var btnRow = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 4, 0, 0) };
            var btnCancel = CreateTgButton("Отмена", Colors.Transparent, Color.FromArgb(20, 255, 255, 255), delegate
            {
                HideModal();
            });
            btnCancel.Width = 85;
            btnCancel.Height = 34;

            var btnSave = CreateTgButton("💾 Сохранить и подключиться", Color.FromRgb(43, 82, 120), Color.FromRgb(58, 107, 153), delegate
            {
                string u = txtUrl.Text.Trim();
                if (!u.StartsWith("ws://", StringComparison.OrdinalIgnoreCase) && !u.StartsWith("wss://", StringComparison.OrdinalIgnoreCase))
                {
                    ShowToast("Адрес должен начинаться с ws:// или wss://", ToastType.Warning);
                    return;
                }
                identity.ServerUrl = u;
                identity.ServerSecret = txtSecret.Text.Trim();
                SaveCurrentIdentity();
                UpdateServerFooterText();
                HideModal();
                ConnectWebSocketAsync();
                ShowToast("Настройки сохранены. Подключение...", ToastType.Info);
            });
            btnSave.Height = 34;
            btnSave.Padding = new Thickness(14, 0, 14, 0);
            btnSave.Margin = new Thickness(8, 0, 0, 0);

            btnRow.Children.Add(btnCancel);
            btnRow.Children.Add(btnSave);
            panel.Children.Add(btnRow);

            ShowModal(panel);
        }

        public static DateTime FormatUnixOrTicks(long timestamp)
        {
            try
            {
                if (timestamp > 1000000000000L && timestamp < 5000000000000L)
                {
                    return DateTimeOffset.FromUnixTimeMilliseconds(timestamp).ToLocalTime().DateTime;
                }
                else if (timestamp > 5000000000000L)
                {
                    return new DateTime(timestamp).ToLocalTime();
                }
            }
            catch { }
            return DateTime.Now;
        }

        public static byte[] DecodeBase64OrDataUrl(string input, out string mimeType)
        {
            mimeType = null;
            if (string.IsNullOrEmpty(input)) return null;
            try
            {
                string clean = input.Trim();
                if (clean.StartsWith("data:", StringComparison.OrdinalIgnoreCase))
                {
                    int commaIdx = clean.IndexOf(',');
                    if (commaIdx >= 0)
                    {
                        string header = clean.Substring(5, commaIdx - 5);
                        int semiIdx = header.IndexOf(';');
                        mimeType = semiIdx >= 0 ? header.Substring(0, semiIdx).Trim() : header.Trim();
                        clean = clean.Substring(commaIdx + 1).Trim();
                    }
                }
                return Convert.FromBase64String(clean);
            }
            catch
            {
                return null;
            }
        }

        private void ApplyTelegramScrollbarTheme()
        {
            string scrollbarXaml = @"
<ResourceDictionary xmlns=""http://schemas.microsoft.com/winfx/2006/xaml/presentation""
                    xmlns:x=""http://schemas.microsoft.com/winfx/2006/xaml"">
    <Style TargetType=""{x:Type ScrollBar}"">
        <Setter Property=""Background"" Value=""Transparent""/>
        <Setter Property=""SnapsToDevicePixels"" Value=""True""/>
        <Setter Property=""OverridesDefaultStyle"" Value=""True""/>
        <Style.Triggers>
            <Trigger Property=""Orientation"" Value=""Vertical"">
                <Setter Property=""Width"" Value=""7""/>
                <Setter Property=""MinWidth"" Value=""7""/>
                <Setter Property=""Template"">
                    <Setter.Value>
                        <ControlTemplate TargetType=""{x:Type ScrollBar}"">
                            <Grid Background=""Transparent"">
                                <Track x:Name=""PART_Track"" IsDirectionReversed=""True"">
                                    <Track.Thumb>
                                        <Thumb>
                                            <Thumb.Template>
                                                <ControlTemplate TargetType=""{x:Type Thumb}"">
                                                    <Border x:Name=""ThumbBorder"" CornerRadius=""3.5"" Background=""#5288C1"" Opacity=""0.3"" Margin=""1,0,1,0""/>
                                                    <ControlTemplate.Triggers>
                                                        <Trigger Property=""IsMouseOver"" Value=""True"">
                                                            <Setter TargetName=""ThumbBorder"" Property=""Opacity"" Value=""0.75""/>
                                                            <Setter TargetName=""ThumbBorder"" Property=""Background"" Value=""#6BA1DB""/>
                                                        </Trigger>
                                                        <Trigger Property=""IsDragging"" Value=""True"">
                                                            <Setter TargetName=""ThumbBorder"" Property=""Opacity"" Value=""0.95""/>
                                                            <Setter TargetName=""ThumbBorder"" Property=""Background"" Value=""#5288C1""/>
                                                        </Trigger>
                                                    </ControlTemplate.Triggers>
                                                </ControlTemplate>
                                            </Thumb.Template>
                                        </Thumb>
                                    </Track.Thumb>
                                </Track>
                            </Grid>
                        </ControlTemplate>
                    </Setter.Value>
                </Setter>
            </Trigger>
            <Trigger Property=""Orientation"" Value=""Horizontal"">
                <Setter Property=""Height"" Value=""7""/>
                <Setter Property=""MinHeight"" Value=""7""/>
                <Setter Property=""Template"">
                    <Setter.Value>
                        <ControlTemplate TargetType=""{x:Type ScrollBar}"">
                            <Grid Background=""Transparent"">
                                <Track x:Name=""PART_Track"" IsDirectionReversed=""False"">
                                    <Track.Thumb>
                                        <Thumb>
                                            <Thumb.Template>
                                                <ControlTemplate TargetType=""{x:Type Thumb}"">
                                                    <Border x:Name=""ThumbBorder"" CornerRadius=""3.5"" Background=""#5288C1"" Opacity=""0.3"" Margin=""0,1,0,1""/>
                                                    <ControlTemplate.Triggers>
                                                        <Trigger Property=""IsMouseOver"" Value=""True"">
                                                            <Setter TargetName=""ThumbBorder"" Property=""Opacity"" Value=""0.75""/>
                                                            <Setter TargetName=""ThumbBorder"" Property=""Background"" Value=""#6BA1DB""/>
                                                        </Trigger>
                                                        <Trigger Property=""IsDragging"" Value=""True"">
                                                            <Setter TargetName=""ThumbBorder"" Property=""Opacity"" Value=""0.95""/>
                                                            <Setter TargetName=""ThumbBorder"" Property=""Background"" Value=""#5288C1""/>
                                                        </Trigger>
                                                    </ControlTemplate.Triggers>
                                                </ControlTemplate>
                                            </Thumb.Template>
                                        </Thumb>
                                    </Track.Thumb>
                                </Track>
                            </Grid>
                        </ControlTemplate>
                    </Setter.Value>
                </Setter>
            </Trigger>
        </Style.Triggers>
    </Style>
</ResourceDictionary>";
            try
            {
                using (var ms = new MemoryStream(Encoding.UTF8.GetBytes(scrollbarXaml)))
                {
                    var resDict = (ResourceDictionary)System.Windows.Markup.XamlReader.Load(ms);
                    if (Application.Current != null)
                    {
                        Application.Current.Resources.MergedDictionaries.Add(resDict);
                    }
                    this.Resources.MergedDictionaries.Add(resDict);
                }
            }
            catch { }
        }

        // =====================================================================
        // ПОСТРОЕНИЕ ПОЛНОГО NATIVE ИНТЕРФЕЙСА (TELEGRAM DESKTOP DARK)
        // =====================================================================
        private void BuildTelegramInterface()
        {
            ApplyTelegramScrollbarTheme();
            rootGrid = new Grid();

            // Слой 0: Основной интерфейс (Боковая панель + Чат)
            var mainContentGrid = new Grid();
            mainContentGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(330) });
            mainContentGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

            // 1. БОКОВАЯ ПАНЕЛЬ (СЛЕВА)
            var sidebarBorder = new Border
            {
                Background = BrushSidebar,
                BorderBrush = BrushBorderSubtle,
                BorderThickness = new Thickness(0, 0, 1, 0)
            };
            var sidebarGrid = new Grid();
            sidebarGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); // 0: Шапка CIPHER
            sidebarGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); // 1: Мой профиль
            sidebarGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); // 2: Поиск
            sidebarGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); // 3: Кнопки
            sidebarGrid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) }); // 4: Контакты
            sidebarGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); // 5: Релей инфо

            // 1.0 Шапка CIPHER
            var brandHeader = new DockPanel { Margin = new Thickness(16, 14, 16, 12) };
            var brandLogoStack = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
            var logoIcon = new TextBlock
            {
                Text = "⬢",
                Foreground = BrushAccentTg,
                FontSize = 18,
                FontWeight = FontWeights.Bold,
                Margin = new Thickness(0, 0, 8, 0)
            };
            var logoText = new TextBlock
            {
                Text = "CIPHER",
                Foreground = Brushes.White,
                FontSize = 16,
                FontWeight = FontWeights.ExtraBold,
                VerticalAlignment = VerticalAlignment.Center
            };
            var badgeText = new Border
            {
                Background = new SolidColorBrush(Color.FromArgb(30, 82, 136, 193)),
                CornerRadius = new CornerRadius(4),
                Padding = new Thickness(5, 1, 5, 1),
                Margin = new Thickness(8, 0, 0, 0),
                VerticalAlignment = VerticalAlignment.Center
            };
            badgeText.Child = new TextBlock
            {
                Text = "E2EE",
                Foreground = BrushAccentTg,
                FontSize = 9.5,
                FontWeight = FontWeights.Bold
            };
            brandLogoStack.Children.Add(logoIcon);
            brandLogoStack.Children.Add(logoText);
            brandLogoStack.Children.Add(badgeText);

            var statusPill = new Border
            {
                Background = new SolidColorBrush(Color.FromArgb(20, 255, 255, 255)),
                CornerRadius = new CornerRadius(12),
                Padding = new Thickness(8, 4, 10, 4),
                HorizontalAlignment = HorizontalAlignment.Right,
                VerticalAlignment = VerticalAlignment.Center,
                Cursor = Cursors.Hand,
                ToolTip = "Настройки подключения к релей-серверу"
            };
            statusPill.MouseDown += delegate { ShowServerSettingsModal(); };
            var statusStack = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
            dotStatus = new Ellipse
            {
                Width = 7,
                Height = 7,
                Fill = new SolidColorBrush(Color.FromRgb(244, 63, 94)),
                Margin = new Thickness(0, 0, 6, 0)
            };
            txtStatus = new TextBlock
            {
                Text = "Офлайн",
                Foreground = BrushTextMuted,
                FontSize = 11,
                FontWeight = FontWeights.SemiBold
            };
            statusStack.Children.Add(dotStatus);
            statusStack.Children.Add(txtStatus);
            statusPill.Child = statusStack;

            brandHeader.Children.Add(brandLogoStack);
            brandHeader.Children.Add(statusPill);
            Grid.SetRow(brandHeader, 0);
            sidebarGrid.Children.Add(brandHeader);

            // 1.1 Мой профиль
            var profileCard = new Border
            {
                Background = new SolidColorBrush(Color.FromArgb(16, 255, 255, 255)),
                CornerRadius = new CornerRadius(10),
                Margin = new Thickness(14, 0, 14, 10),
                Padding = new Thickness(12, 10, 12, 10),
                Cursor = Cursors.Hand,
                ToolTip = "Открыть мой профиль и управление ключами"
            };
            profileCard.MouseDown += delegate { ShowProfileModal(); };
            var profileDock = new DockPanel();
            var myAvatar = CreateAvatarCircle(this.userName, this.identity.Id, 42);
            var myMeta = new StackPanel { Margin = new Thickness(12, 0, 0, 0), VerticalAlignment = VerticalAlignment.Center };
            var myNameRow = new StackPanel { Orientation = Orientation.Horizontal };
            myNameTxt = new TextBlock { Text = this.userName, Foreground = Brushes.White, FontWeight = FontWeights.Bold, FontSize = 14 };
            var myChip = new Border
            {
                Background = new SolidColorBrush(Color.FromArgb(30, 6, 182, 212)),
                CornerRadius = new CornerRadius(4),
                Padding = new Thickness(4, 1, 4, 1),
                Margin = new Thickness(8, 0, 0, 0)
            };
            myChip.Child = new TextBlock { Text = "P-256", Foreground = new SolidColorBrush(Color.FromRgb(6, 182, 212)), FontSize = 9.5, FontWeight = FontWeights.Bold };
            myNameRow.Children.Add(myNameTxt);
            myNameRow.Children.Add(myChip);
            string idShort = this.identity.Id.Length > 14 ? (this.identity.Id.Substring(0, 14) + "...") : this.identity.Id;
            var myIdTxt = new TextBlock { Text = "ID: " + idShort, Foreground = BrushTextMuted, FontSize = 11, Margin = new Thickness(0, 2, 0, 0) };
            myMeta.Children.Add(myNameRow);
            myMeta.Children.Add(myIdTxt);

            var profileActions = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
            var btnQrIcon = CreateTgIconButton("📱", 13, Color.FromArgb(20, 255, 255, 255), Color.FromArgb(40, 255, 255, 255), delegate
            {
                ShowMyQrModal();
            });
            btnQrIcon.ToolTip = "Показать QR-код для добавления со смартфона";
            btnQrIcon.Margin = new Thickness(0, 0, 4, 0);

            var btnCopyKey = CreateTgIconButton("🔑", 14, Color.FromArgb(20, 255, 255, 255), Color.FromArgb(40, 255, 255, 255), delegate
            {
                Clipboard.SetText(this.identity.PublicKeyB64);
                ShowToast("Открытый ключ скопирован в буфер обмена", ToastType.Success);
            });
            btnCopyKey.ToolTip = "Скопировать открытый ключ";

            profileActions.Children.Add(btnQrIcon);
            profileActions.Children.Add(btnCopyKey);

            profileDock.Children.Add(myAvatar);
            profileDock.Children.Add(myMeta);
            profileDock.Children.Add(profileActions);
            profileCard.Child = profileDock;
            Grid.SetRow(profileCard, 1);
            sidebarGrid.Children.Add(profileCard);

            // 1.2 Поиск
            var searchContainer = new Border
            {
                Background = BrushInputBox,
                CornerRadius = new CornerRadius(18),
                Margin = new Thickness(14, 0, 14, 10),
                Padding = new Thickness(14, 8, 14, 8),
                BorderBrush = BrushBorderSubtle,
                BorderThickness = new Thickness(1)
            };
            var searchGrid = new Grid();
            txtSearchPlaceholder = new TextBlock
            {
                Text = "🔍  Поиск по чатам (Ctrl+F)...",
                Foreground = BrushTextMuted,
                FontSize = 12,
                IsHitTestVisible = false,
                VerticalAlignment = VerticalAlignment.Center
            };
            txtSearch = new TextBox
            {
                Background = Brushes.Transparent,
                Foreground = Brushes.White,
                BorderThickness = new Thickness(0),
                FontSize = 12,
                CaretBrush = Brushes.White,
                VerticalAlignment = VerticalAlignment.Center
            };
            txtSearch.TextChanged += delegate
            {
                txtSearchPlaceholder.Visibility = string.IsNullOrEmpty(txtSearch.Text) ? Visibility.Visible : Visibility.Collapsed;
                RenderContactList();
            };
            searchGrid.Children.Add(txtSearchPlaceholder);
            searchGrid.Children.Add(txtSearch);
            searchContainer.Child = searchGrid;
            Grid.SetRow(searchContainer, 2);
            sidebarGrid.Children.Add(searchContainer);

            // 1.3 Кнопки действий
            var actionsGrid = new Grid { Margin = new Thickness(14, 0, 14, 10) };
            actionsGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            actionsGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            actionsGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(72) });

            var btnAddContact = CreateTgButton("+ Контакт", Color.FromRgb(43, 82, 120), Color.FromRgb(58, 107, 153), delegate
            {
                ShowAddContactModal();
            });
            Grid.SetColumn(btnAddContact, 0);

            var btnAddGroup = CreateTgButton("👥 Группа", Color.FromArgb(35, 43, 82, 120), Color.FromArgb(60, 58, 107, 153), delegate
            {
                ShowCreateGroupModal();
            });
            btnAddGroup.Margin = new Thickness(6, 0, 0, 0);
            Grid.SetColumn(btnAddGroup, 1);

            var btnWindow2 = CreateTgButton("Окно 2", Color.FromArgb(20, 255, 255, 255), Color.FromArgb(35, 255, 255, 255), delegate
            {
                string target = (this.userName == "\u0410\u043B\u0438\u0441\u0430") ? "\u0411\u043E\u0431" : "\u0410\u043B\u0438\u0441\u0430";
                string arg = (target == "\u0411\u043E\u0431") ? "Bob" : "Alice";
                try
                {
                    var p = new ProcessStartInfo
                    {
                        FileName = Process.GetCurrentProcess().MainModule.FileName,
                        Arguments = arg,
                        WorkingDirectory = Program.AppDir
                    };
                    Process.Start(p);
                    ShowToast("Запущено Окно 2 (" + target + ")", ToastType.Info);
                }
                catch
                {
                    var win2 = new MainWindow(target);
                    win2.Show();
                }
            });
            btnWindow2.Margin = new Thickness(6, 0, 0, 0);
            Grid.SetColumn(btnWindow2, 2);

            actionsGrid.Children.Add(btnAddContact);
            actionsGrid.Children.Add(btnAddGroup);
            actionsGrid.Children.Add(btnWindow2);
            Grid.SetRow(actionsGrid, 3);
            sidebarGrid.Children.Add(actionsGrid);

            // 1.4 Список чатов
            var scrollContacts = new ScrollViewer
            {
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                Padding = new Thickness(8, 0, 8, 0)
            };
            panelContacts = new StackPanel();
            scrollContacts.Content = panelContacts;
            Grid.SetRow(scrollContacts, 4);
            sidebarGrid.Children.Add(scrollContacts);

            // 1.5 Статус сервера
            var serverFooter = new Border
            {
                Padding = new Thickness(14, 8, 14, 8),
                BorderBrush = BrushBorderSubtle,
                BorderThickness = new Thickness(0, 1, 0, 0),
                Cursor = Cursors.Hand,
                ToolTip = "Настройки подключения к релей-серверу"
            };
            serverFooter.MouseDown += delegate { ShowServerSettingsModal(); };
            this.serverText = new TextBlock
            {
                Text = "Слепой релей: 127.0.0.1:8080 🔒",
                Foreground = new SolidColorBrush(Color.FromRgb(80, 95, 115)),
                FontSize = 10.5
            };
            UpdateServerFooterText();
            serverFooter.Child = this.serverText;
            Grid.SetRow(serverFooter, 5);
            sidebarGrid.Children.Add(serverFooter);

            sidebarBorder.Child = sidebarGrid;
            Grid.SetColumn(sidebarBorder, 0);
            mainContentGrid.Children.Add(sidebarBorder);

            // 2. ОБЛАСТЬ ЧАТА (СПРАВА)
            chatAreaGrid = new Grid();
            chatAreaGrid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(60) }); // 0: Шапка чата
            chatAreaGrid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) }); // 1: Сообщения
            chatAreaGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); // 2: Превью фото
            chatAreaGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); // 3: Панель ответа (Reply)
            chatAreaGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); // 4: Панель редактирования (Edit)
            chatAreaGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); // 5: Запись ГС
            chatAreaGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); // 6: Поле ввода

            // 2.0 Шапка чата
            var chatHeaderBorder = new Border
            {
                Background = BrushHeader,
                BorderBrush = BrushBorderSubtle,
                BorderThickness = new Thickness(0, 0, 0, 1),
                Padding = new Thickness(20, 0, 20, 0)
            };
            var chatHeaderDock = new DockPanel();

            var contactInfoLeft = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
            activeAvatarContainer = new Border { Width = 38, Height = 38, CornerRadius = new CornerRadius(19), Margin = new Thickness(0, 0, 12, 0) };
            var contactTitles = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
            txtActiveName = new TextBlock { Text = "Выберите чат", Foreground = Brushes.White, FontSize = 14.5, FontWeight = FontWeights.Bold };
            txtActiveStatus = new TextBlock { Text = "Сквозной шифр активен", Foreground = BrushAccentTg, FontSize = 11, Margin = new Thickness(0, 2, 0, 0) };
            contactTitles.Children.Add(txtActiveName);
            contactTitles.Children.Add(txtActiveStatus);
            contactInfoLeft.Children.Add(activeAvatarContainer);
            contactInfoLeft.Children.Add(contactTitles);

            var headerControlsRight = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, VerticalAlignment = VerticalAlignment.Center };

            destructPill = new Border
            {
                Background = new SolidColorBrush(Color.FromArgb(25, 244, 63, 94)),
                BorderBrush = new SolidColorBrush(Color.FromArgb(60, 244, 63, 94)),
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(14),
                Padding = new Thickness(10, 4, 10, 4),
                Cursor = Cursors.Hand
            };
            txtDestructLabel = new TextBlock
            {
                Text = "💥 Самоуничтожение: Выкл",
                Foreground = new SolidColorBrush(Color.FromRgb(253, 164, 175)),
                FontSize = 11,
                FontWeight = FontWeights.SemiBold
            };
            destructPill.Child = txtDestructLabel;
            destructPill.MouseDown += delegate { ToggleDestructTimer(); };

            var btnInfo = CreateTgIconButton("ℹ", 15, Color.FromArgb(20, 255, 255, 255), Color.FromArgb(40, 255, 255, 255), delegate
            {
                ShowContactKeyInfo();
            });
            btnInfo.Margin = new Thickness(10, 0, 0, 0);

            var btnSearch = CreateTgIconButton("🔍", 14, Color.FromArgb(20, 255, 255, 255), Color.FromArgb(40, 255, 255, 255), delegate
            {
                ToggleInChatSearch();
            });
            btnSearch.Margin = new Thickness(10, 0, 0, 0);
            btnSearch.ToolTip = "Поиск по сообщениям в чате";

            headerControlsRight.Children.Add(btnSearch);
            headerControlsRight.Children.Add(destructPill);
            headerControlsRight.Children.Add(btnInfo);

            chatHeaderDock.Children.Add(contactInfoLeft);
            chatHeaderDock.Children.Add(headerControlsRight);
            chatHeaderBorder.Child = chatHeaderDock;
            Grid.SetRow(chatHeaderBorder, 0);
            chatAreaGrid.Children.Add(chatHeaderBorder);

            // 2.1 Лента сообщений
            var messagesLayerGrid = new Grid();
            messagesLayerGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); // 0: Поиск в чате
            messagesLayerGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); // 1: Закрепленное сообщение
            messagesLayerGrid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) }); // 2: Сообщения

            // 2.0.1 Панель поиска в чате
            inChatSearchBar = new Border
            {
                Background = new SolidColorBrush(Color.FromArgb(245, 21, 31, 46)),
                BorderBrush = BrushBorderSubtle,
                BorderThickness = new Thickness(0, 0, 0, 1),
                Padding = new Thickness(16, 6, 16, 6),
                Visibility = Visibility.Collapsed
            };
            var searchDock = new DockPanel();
            var btnSearchClose = CreateTgIconButton("✕", 11, Colors.Transparent, Color.FromArgb(40, 255, 255, 255), delegate
            {
                CloseInChatSearch();
            });
            btnSearchClose.HorizontalAlignment = HorizontalAlignment.Right;
            btnSearchClose.VerticalAlignment = VerticalAlignment.Center;

            var navStack = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 10, 0) };
            txtInChatCount = new TextBlock { Text = "0 совпадений", Foreground = BrushTextMuted, FontSize = 11, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 8, 0) };
            var btnPrev = CreateTgIconButton("▲", 10, Color.FromArgb(30, 255, 255, 255), Color.FromArgb(60, 255, 255, 255), delegate { NavigateInChatSearch(-1); });
            btnPrev.Margin = new Thickness(0, 0, 4, 0);
            var btnNext = CreateTgIconButton("▼", 10, Color.FromArgb(30, 255, 255, 255), Color.FromArgb(60, 255, 255, 255), delegate { NavigateInChatSearch(1); });
            navStack.Children.Add(txtInChatCount);
            navStack.Children.Add(btnPrev);
            navStack.Children.Add(btnNext);

            txtInChatQuery = new TextBox
            {
                Background = BrushInputBox,
                Foreground = Brushes.White,
                BorderThickness = new Thickness(1),
                BorderBrush = BrushBorderSubtle,
                Padding = new Thickness(8, 4, 8, 4),
                FontSize = 12
            };
            txtInChatQuery.TextChanged += delegate { PerformInChatSearch(txtInChatQuery.Text); };
            txtInChatQuery.KeyDown += delegate(object s, KeyEventArgs e)
            {
                if (e.Key == Key.Enter) NavigateInChatSearch((Keyboard.Modifiers & ModifierKeys.Shift) != 0 ? -1 : 1);
                else if (e.Key == Key.Escape) CloseInChatSearch();
            };

            searchDock.Children.Add(btnSearchClose);
            searchDock.Children.Add(navStack);
            searchDock.Children.Add(txtInChatQuery);
            inChatSearchBar.Child = searchDock;
            Grid.SetRow(inChatSearchBar, 0);

            // 2.0.2 Панель закрепленного сообщения
            pinnedBanner = new Border
            {
                Background = new SolidColorBrush(Color.FromArgb(240, 26, 38, 57)),
                BorderBrush = BrushBorderSubtle,
                BorderThickness = new Thickness(0, 0, 0, 1),
                Padding = new Thickness(16, 6, 16, 6),
                Visibility = Visibility.Collapsed,
                Cursor = Cursors.Hand
            };
            var pinnedDock = new DockPanel();
            var pinIcon = new TextBlock { Text = "📌", FontSize = 13, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 8, 0) };
            var btnUnpin = CreateTgIconButton("✕", 11, Colors.Transparent, Color.FromArgb(40, 255, 255, 255), delegate
            {
                if (activeContact != null) UnpinMessage(activeContact.Id);
            });
            btnUnpin.HorizontalAlignment = HorizontalAlignment.Right;
            btnUnpin.VerticalAlignment = VerticalAlignment.Center;

            var pinTextStack = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
            var pinTitle = new TextBlock { Text = "Закрепленное сообщение", Foreground = BrushAccentTg, FontSize = 10.5, FontWeight = FontWeights.Bold };
            txtPinnedSnippet = new TextBlock { Text = "...", Foreground = Brushes.White, FontSize = 11.5, TextTrimming = TextTrimming.CharacterEllipsis };
            pinTextStack.Children.Add(pinTitle);
            pinTextStack.Children.Add(txtPinnedSnippet);

            pinnedDock.Children.Add(pinIcon);
            pinnedDock.Children.Add(btnUnpin);
            pinnedDock.Children.Add(pinTextStack);
            pinnedBanner.Child = pinnedDock;
            pinnedBanner.MouseDown += delegate(object s, MouseButtonEventArgs e)
            {
                if (e.OriginalSource != btnUnpin && activeContact != null && pinnedMessages.ContainsKey(activeContact.Id))
                {
                    ScrollToAndHighlightMessage(pinnedMessages[activeContact.Id]);
                }
            };
            Grid.SetRow(pinnedBanner, 1);

            scrollMessages = new ScrollViewer
            {
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                Padding = new Thickness(24, 16, 24, 16),
                Background = BrushBgMain
            };
            
            // Настоящая инерционная плавная анимация прокрутки (Smooth Scrolling с затуханием)
            double targetScrollOffset = 0;
            DispatcherTimer smoothScrollTimer = new DispatcherTimer(DispatcherPriority.Render);
            smoothScrollTimer.Interval = TimeSpan.FromMilliseconds(12);
            smoothScrollTimer.Tick += delegate
            {
                double current = scrollMessages.VerticalOffset;
                double diff = targetScrollOffset - current;
                if (Math.Abs(diff) < 0.6)
                {
                    scrollMessages.ScrollToVerticalOffset(targetScrollOffset);
                    smoothScrollTimer.Stop();
                }
                else
                {
                    // Мягкая экспоненциальная интерполяция (lerp)
                    scrollMessages.ScrollToVerticalOffset(current + (diff * 0.22));
                }
            };

            scrollMessages.PreviewMouseWheel += delegate(object sender, MouseWheelEventArgs e)
            {
                e.Handled = true;
                if (!smoothScrollTimer.IsEnabled)
                {
                    targetScrollOffset = scrollMessages.VerticalOffset;
                }
                // Накапливаем шаг прокрутки
                targetScrollOffset -= (e.Delta * 0.85);
                targetScrollOffset = Math.Max(0, Math.Min(scrollMessages.ScrollableHeight, targetScrollOffset));
                smoothScrollTimer.Start();
            };

            panelMessages = new StackPanel();
            scrollMessages.Content = panelMessages;

            // Заглушка, когда чат не выбран
            emptyChatPlaceholder = new Border
            {
                Background = Brushes.Transparent,
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center,
                Visibility = Visibility.Visible
            };
            var emptyStack = new StackPanel { HorizontalAlignment = HorizontalAlignment.Center };
            var lockIcon = new TextBlock
            {
                Text = "🔒",
                FontSize = 40,
                Foreground = new SolidColorBrush(Color.FromArgb(120, 82, 136, 193)),
                HorizontalAlignment = HorizontalAlignment.Center,
                Margin = new Thickness(0, 0, 0, 14)
            };
            var emptyTitle = new TextBlock
            {
                Text = "Выберите собеседника для начала защищенной переписки",
                Foreground = Brushes.White,
                FontSize = 14,
                FontWeight = FontWeights.SemiBold,
                HorizontalAlignment = HorizontalAlignment.Center
            };
            var emptySubtitle = new TextBlock
            {
                Text = "Все сообщения, фотографии и голосовые шифруются на вашем ПК",
                Foreground = BrushTextMuted,
                FontSize = 12,
                HorizontalAlignment = HorizontalAlignment.Center,
                Margin = new Thickness(0, 6, 0, 0)
            };
            emptyStack.Children.Add(lockIcon);
            emptyStack.Children.Add(emptyTitle);
            emptyStack.Children.Add(emptySubtitle);
            emptyChatPlaceholder.Child = emptyStack;

            Grid.SetRow(scrollMessages, 2);
            Grid.SetRow(emptyChatPlaceholder, 2);

            messagesLayerGrid.Children.Add(inChatSearchBar);
            messagesLayerGrid.Children.Add(pinnedBanner);
            messagesLayerGrid.Children.Add(scrollMessages);
            messagesLayerGrid.Children.Add(emptyChatPlaceholder);
            Grid.SetRow(messagesLayerGrid, 1);
            chatAreaGrid.Children.Add(messagesLayerGrid);

            // 2.2 Превью фото
            attachmentPreviewBar = new Border
            {
                Background = new SolidColorBrush(Color.FromArgb(40, 82, 136, 193)),
                BorderBrush = new SolidColorBrush(Color.FromArgb(60, 82, 136, 193)),
                BorderThickness = new Thickness(0, 1, 0, 0),
                Padding = new Thickness(20, 8, 20, 8),
                Visibility = Visibility.Collapsed
            };
            var previewDock = new DockPanel();
            txtPreviewInfo = new TextBlock
            {
                Text = "📷 Фото готово к отправке",
                Foreground = Brushes.White,
                FontSize = 12.5,
                VerticalAlignment = VerticalAlignment.Center
            };
            var btnRemovePreview = CreateTgIconButton("✕", 13, Colors.Transparent, Color.FromArgb(40, 244, 63, 94), delegate
            {
                ClearAttachedPhoto();
            });
            btnRemovePreview.HorizontalAlignment = HorizontalAlignment.Right;
            previewDock.Children.Add(txtPreviewInfo);
            previewDock.Children.Add(btnRemovePreview);
            attachmentPreviewBar.Child = previewDock;
            Grid.SetRow(attachmentPreviewBar, 2);
            chatAreaGrid.Children.Add(attachmentPreviewBar);

            // 2.3 Панель ответа на сообщение (Reply Bar)
            replyPreviewBar = new Border
            {
                Background = new SolidColorBrush(Color.FromArgb(30, 82, 136, 193)),
                BorderBrush = BrushBorderSubtle,
                BorderThickness = new Thickness(0, 1, 0, 0),
                Padding = new Thickness(16, 6, 16, 6),
                Visibility = Visibility.Collapsed
            };
            var replyDock = new DockPanel();
            var replyIcon = new TextBlock
            {
                Text = "↩",
                Foreground = BrushAccentTg,
                FontSize = 18,
                FontWeight = FontWeights.Bold,
                Margin = new Thickness(0, 0, 12, 0),
                VerticalAlignment = VerticalAlignment.Center
            };
            var replyLine = new Border
            {
                Width = 2.5,
                Background = BrushAccentTg,
                CornerRadius = new CornerRadius(1.5),
                Margin = new Thickness(0, 0, 10, 0)
            };
            var replyTextStack = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
            txtReplyName = new TextBlock
            {
                Text = "Имя",
                Foreground = BrushAccentTg,
                FontSize = 12,
                FontWeight = FontWeights.Bold
            };
            txtReplyContent = new TextBlock
            {
                Text = "Текст сообщения...",
                Foreground = Brushes.White,
                FontSize = 11.5,
                TextTrimming = TextTrimming.CharacterEllipsis,
                MaxWidth = 450
            };
            replyTextStack.Children.Add(txtReplyName);
            replyTextStack.Children.Add(txtReplyContent);

            var btnCancelReply = CreateTgIconButton("✕", 12, Colors.Transparent, Color.FromArgb(40, 255, 255, 255), delegate
            {
                ClearReply();
            });
            btnCancelReply.HorizontalAlignment = HorizontalAlignment.Right;

            replyDock.Children.Add(replyIcon);
            replyDock.Children.Add(replyLine);
            replyDock.Children.Add(replyTextStack);
            replyDock.Children.Add(btnCancelReply);
            replyPreviewBar.Child = replyDock;
            Grid.SetRow(replyPreviewBar, 3);
            chatAreaGrid.Children.Add(replyPreviewBar);

            // 2.4 Панель редактирования сообщения (Edit Bar)
            editPreviewBar = new Border
            {
                Background = new SolidColorBrush(Color.FromArgb(30, 245, 158, 11)),
                BorderBrush = BrushBorderSubtle,
                BorderThickness = new Thickness(0, 1, 0, 0),
                Padding = new Thickness(16, 6, 16, 6),
                Visibility = Visibility.Collapsed
            };
            var editDock = new DockPanel();
            var editIcon = new TextBlock
            {
                Text = "✏️",
                FontSize = 14,
                Margin = new Thickness(0, 0, 10, 0),
                VerticalAlignment = VerticalAlignment.Center
            };
            var editLine = new Border
            {
                Width = 2.5,
                Background = new SolidColorBrush(Color.FromRgb(245, 158, 11)),
                CornerRadius = new CornerRadius(1.5),
                Margin = new Thickness(0, 0, 10, 0)
            };
            var editTextStack = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
            var lblEditTitle = new TextBlock
            {
                Text = "Редактирование",
                Foreground = new SolidColorBrush(Color.FromRgb(245, 158, 11)),
                FontSize = 12,
                FontWeight = FontWeights.Bold
            };
            txtEditContent = new TextBlock
            {
                Text = "Текст сообщения...",
                Foreground = Brushes.White,
                FontSize = 11.5,
                TextTrimming = TextTrimming.CharacterEllipsis,
                MaxWidth = 450
            };
            editTextStack.Children.Add(lblEditTitle);
            editTextStack.Children.Add(txtEditContent);

            var btnCancelEdit = CreateTgIconButton("✕", 12, Colors.Transparent, Color.FromArgb(40, 255, 255, 255), delegate
            {
                ClearEditMode();
            });
            btnCancelEdit.HorizontalAlignment = HorizontalAlignment.Right;

            editDock.Children.Add(editIcon);
            editDock.Children.Add(editLine);
            editDock.Children.Add(editTextStack);
            editDock.Children.Add(btnCancelEdit);
            editPreviewBar.Child = editDock;
            Grid.SetRow(editPreviewBar, 4);
            chatAreaGrid.Children.Add(editPreviewBar);

            // 2.5 Панель записи ГС
            voiceRecordingBar = new Border
            {
                Background = new SolidColorBrush(Color.FromArgb(50, 244, 63, 94)),
                BorderBrush = new SolidColorBrush(Color.FromArgb(80, 244, 63, 94)),
                BorderThickness = new Thickness(0, 1, 0, 0),
                Padding = new Thickness(20, 10, 20, 10),
                Visibility = Visibility.Collapsed
            };
            var voiceDock = new DockPanel();
            var voiceLeft = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
            var recDot = new Ellipse { Width = 10, Height = 10, Fill = new SolidColorBrush(Color.FromRgb(244, 63, 94)), Margin = new Thickness(0, 0, 8, 0) };
            txtVoiceTimer = new TextBlock { Text = "00:00", Foreground = Brushes.White, FontWeight = FontWeights.Bold, FontSize = 14 };
            voiceLeft.Children.Add(recDot);
            voiceLeft.Children.Add(txtVoiceTimer);

            var voiceRight = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
            var btnCancelVoice = CreateTgButton("✕ Отмена", Color.FromArgb(30, 255, 255, 255), Color.FromArgb(50, 255, 255, 255), delegate
            {
                CancelVoiceRecording();
            });
            var btnSendVoice = CreateTgButton("➤ Отправить ГС", Color.FromRgb(244, 63, 94), Color.FromRgb(225, 29, 72), delegate
            {
                StopAndSendVoiceRecording();
            });
            btnSendVoice.Margin = new Thickness(8, 0, 0, 0);
            voiceRight.Children.Add(btnCancelVoice);
            voiceRight.Children.Add(btnSendVoice);
            voiceDock.Children.Add(voiceLeft);
            voiceDock.Children.Add(voiceRight);
            voiceRecordingBar.Child = voiceDock;
            Grid.SetRow(voiceRecordingBar, 5);
            chatAreaGrid.Children.Add(voiceRecordingBar);

            // 2.6 Нижняя панель ввода
            var inputFooterBorder = new Border
            {
                Background = BrushInputArea,
                BorderBrush = BrushBorderSubtle,
                BorderThickness = new Thickness(0, 1, 0, 0),
                Padding = new Thickness(16, 10, 16, 10)
            };
            var inputDockGrid = new Grid();
            inputDockGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(40) });
            inputDockGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            inputDockGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(40) });
            inputDockGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(44) });

            var btnAttach = CreateTgIconButton("📎", 17, Colors.Transparent, Color.FromArgb(25, 255, 255, 255), delegate
            {
                ChooseAttachmentFile();
            });
            Grid.SetColumn(btnAttach, 0);

            var textBoxContainer = new Border
            {
                Background = BrushInputBox,
                CornerRadius = new CornerRadius(18),
                Padding = new Thickness(14, 8, 14, 8),
                Margin = new Thickness(6, 0, 6, 0),
                BorderBrush = BrushBorderSubtle,
                BorderThickness = new Thickness(1)
            };
            var inputGrid = new Grid();
            txtInputPlaceholder = new TextBlock
            {
                Text = "Напишите зашифрованное сообщение... (Enter - отправить, Shift+Enter - перенос)",
                Foreground = BrushTextMuted,
                FontSize = 13,
                IsHitTestVisible = false,
                VerticalAlignment = VerticalAlignment.Center
            };
            txtInput = new TextBox
            {
                Background = Brushes.Transparent,
                Foreground = Brushes.White,
                BorderThickness = new Thickness(0),
                FontSize = 13.5,
                AcceptsReturn = true,
                MaxHeight = 120,
                CaretBrush = Brushes.White,
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                VerticalAlignment = VerticalAlignment.Center
            };
            txtInput.TextChanged += delegate
            {
                txtInputPlaceholder.Visibility = string.IsNullOrEmpty(txtInput.Text) ? Visibility.Visible : Visibility.Collapsed;
                NotifyTyping();
                if (activeContact != null)
                {
                    if (!string.IsNullOrEmpty(txtInput.Text)) chatDrafts[activeContact.Id] = txtInput.Text;
                    else chatDrafts.Remove(activeContact.Id);
                }
            };
            txtInput.PreviewKeyDown += delegate(object s, KeyEventArgs e)
            {
                if (e.Key == Key.Enter && (Keyboard.Modifiers & ModifierKeys.Shift) == 0)
                {
                    e.Handled = true;
                    SendMessageFromInput();
                }
                else if (e.Key == Key.Escape)
                {
                    if (editingMessage != null) { ClearEditMode(); txtInput.Text = ""; e.Handled = true; }
                    else if (replyingMessage != null) { ClearReply(); e.Handled = true; }
                }
            };
            inputGrid.Children.Add(txtInputPlaceholder);
            inputGrid.Children.Add(txtInput);
            textBoxContainer.Child = inputGrid;
            Grid.SetColumn(textBoxContainer, 1);

            var btnVoice = CreateTgIconButton("🎤", 17, Colors.Transparent, Color.FromArgb(25, 255, 255, 255), delegate
            {
                StartVoiceRecording();
            });
            Grid.SetColumn(btnVoice, 2);

            var btnSend = CreateTgIconButton("➤", 16, Color.FromRgb(43, 82, 120), Color.FromRgb(58, 107, 153), delegate
            {
                SendMessageFromInput();
            });
            btnSend.Margin = new Thickness(4, 0, 0, 0);
            Grid.SetColumn(btnSend, 3);

            inputDockGrid.Children.Add(btnAttach);
            inputDockGrid.Children.Add(textBoxContainer);
            inputDockGrid.Children.Add(btnVoice);
            inputDockGrid.Children.Add(btnSend);
            inputFooterBorder.Child = inputDockGrid;
            Grid.SetRow(inputFooterBorder, 6);
            chatAreaGrid.Children.Add(inputFooterBorder);

            Grid.SetColumn(chatAreaGrid, 1);
            mainContentGrid.Children.Add(chatAreaGrid);

            rootGrid.Children.Add(mainContentGrid);

            // Слой 1: Модальный оверлей
            modalOverlayGrid = new Grid
            {
                Background = new SolidColorBrush(Color.FromArgb(170, 0, 0, 0)),
                Visibility = Visibility.Collapsed
            };
            modalDialogCard = new Border
            {
                Background = BrushHeader,
                BorderBrush = new SolidColorBrush(Color.FromRgb(43, 82, 120)),
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(14),
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center,
                Effect = new DropShadowEffect
                {
                    Color = Colors.Black,
                    Direction = 270,
                    ShadowDepth = 6,
                    Opacity = 0.5,
                    BlurRadius = 24
                }
            };
            modalContentStack = new StackPanel();
            modalDialogCard.Child = modalContentStack;
            modalOverlayGrid.Children.Add(modalDialogCard);
            rootGrid.Children.Add(modalOverlayGrid);

            // Слой 2: Floating In-App Toast
            toastCard = new Border
            {
                Background = new SolidColorBrush(Color.FromRgb(30, 41, 59)), // #1E293B
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(14),
                Padding = new Thickness(16, 9, 18, 9),
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Top,
                Margin = new Thickness(0, 18, 0, 0),
                Visibility = Visibility.Collapsed,
                Cursor = Cursors.Hand,
                Effect = new DropShadowEffect
                {
                    Color = Colors.Black,
                    Direction = 270,
                    ShadowDepth = 4,
                    Opacity = 0.45,
                    BlurRadius = 18
                }
            };
            var toastStack = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
            toastIconTxt = new TextBlock
            {
                FontSize = 14,
                FontWeight = FontWeights.Bold,
                Margin = new Thickness(0, 0, 10, 0),
                VerticalAlignment = VerticalAlignment.Center
            };
            toastBodyTxt = new TextBlock
            {
                Foreground = Brushes.White,
                FontSize = 13,
                FontWeight = FontWeights.SemiBold,
                VerticalAlignment = VerticalAlignment.Center
            };
            toastStack.Children.Add(toastIconTxt);
            toastStack.Children.Add(toastBodyTxt);
            toastCard.Child = toastStack;
            toastCard.MouseDown += delegate { HideToast(); };
            rootGrid.Children.Add(toastCard);

            this.Content = rootGrid;

            // Drag & Drop файлов
            this.AllowDrop = true;
            this.DragOver += delegate(object s, DragEventArgs e)
            {
                if (e.Data.GetDataPresent(DataFormats.FileDrop)) e.Effects = DragDropEffects.Copy;
                else e.Effects = DragDropEffects.None;
                e.Handled = true;
            };
            this.Drop += delegate(object s, DragEventArgs e)
            {
                if (e.Data.GetDataPresent(DataFormats.FileDrop))
                {
                    string[] files = (string[])e.Data.GetData(DataFormats.FileDrop);
                    if (files != null && files.Length > 0)
                    {
                        AttachFile(files[0]);
                    }
                }
            };

            // Ctrl+V вставка скриншота
            this.PreviewKeyDown += delegate(object s, KeyEventArgs e)
            {
                if (e.Key == Key.V && (Keyboard.Modifiers & ModifierKeys.Control) != 0)
                {
                    if (Clipboard.ContainsImage())
                    {
                        var img = Clipboard.GetImage();
                        if (img != null)
                        {
                            var enc = new PngBitmapEncoder();
                            enc.Frames.Add(BitmapFrame.Create(img));
                            using (var ms = new MemoryStream())
                            {
                                enc.Save(ms);
                                attachedPhotoB64 = Convert.ToBase64String(ms.ToArray());
                                attachedPhotoName = "Скриншот_" + DateTime.Now.ToString("HH-mm-ss") + ".png";
                                txtPreviewInfo.Text = "📷 " + attachedPhotoName + " (" + (ms.Length / 1024) + " KB)";
                                attachmentPreviewBar.Visibility = Visibility.Visible;
                                ShowToast("Скриншот прикреплен из буфера обмена", ToastType.Info);
                            }
                        }
                    }
                }
                if (e.Key == Key.F && (Keyboard.Modifiers & ModifierKeys.Control) != 0)
                {
                    txtSearch.Focus();
                }
                if (e.Key == Key.Escape)
                {
                    ClearReply();
                }
            };
        }

        // =====================================================================
        // СЕТЬ (WEBSOCKET CLIENT)
        // =====================================================================
        private async void ConnectWebSocketAsync()
        {
            bool needRetry = false;
            try
            {
                if (webSocket != null)
                {
                    try { webSocket.Dispose(); } catch { }
                }

                wsCts = new CancellationTokenSource();
                webSocket = new ClientWebSocket();

                Dispatcher.Invoke(new Action(delegate
                {
                    txtStatus.Text = "Подключение...";
                    dotStatus.Fill = Brushes.Orange;
                    UpdateServerFooterText();
                }));

                string sUrl = !string.IsNullOrEmpty(identity.ServerUrl) ? identity.ServerUrl.Trim() : "wss://fotowaqu.ru";
                if (!sUrl.StartsWith("ws://") && !sUrl.StartsWith("wss://"))
                {
                    sUrl = "ws://" + sUrl;
                }

                await webSocket.ConnectAsync(new Uri(sUrl), wsCts.Token);

                var regDict = new Dictionary<string, object>
                {
                    { "action", "register" },
                    { "clientId", identity.Id }
                };
                if (!string.IsNullOrEmpty(identity.ServerSecret))
                {
                    regDict["serverSecret"] = identity.ServerSecret;
                }
                byte[] regBytes = Encoding.UTF8.GetBytes(json.Serialize(regDict));
                await webSocket.SendAsync(new ArraySegment<byte>(regBytes), WebSocketMessageType.Text, true, wsCts.Token);

                Dispatcher.Invoke(new Action(delegate
                {
                    txtStatus.Text = "В сети";
                    dotStatus.Fill = new SolidColorBrush(Color.FromRgb(16, 185, 129));
                    UpdateServerFooterText();
                }));

                var buffer = new byte[1024 * 512];
                while (webSocket.State == WebSocketState.Open && !wsCts.Token.IsCancellationRequested)
                {
                    var ms = new MemoryStream();
                    WebSocketReceiveResult result;
                    do
                    {
                        result = await webSocket.ReceiveAsync(new ArraySegment<byte>(buffer), wsCts.Token);
                        if (result.MessageType == WebSocketMessageType.Close) break;
                        ms.Write(buffer, 0, result.Count);
                    }
                    while (!result.EndOfMessage);

                    if (result.MessageType == WebSocketMessageType.Close) break;

                    string msgText = Encoding.UTF8.GetString(ms.ToArray());
                    HandleIncomingWsPacket(msgText);
                }
            }
            catch
            {
                Dispatcher.Invoke(new Action(delegate
                {
                    txtStatus.Text = "Офлайн";
                    dotStatus.Fill = new SolidColorBrush(Color.FromRgb(244, 63, 94));
                    UpdateServerFooterText();
                }));
                needRetry = true;
            }

            if (needRetry)
            {
                await Task.Delay(3000);
                ConnectWebSocketAsync();
            }
        }

        private async void SendReadReceipt(string toClientId, string messageId)
        {
            if (webSocket == null || webSocket.State != WebSocketState.Open || string.IsNullOrEmpty(toClientId) || string.IsNullOrEmpty(messageId)) return;
            try
            {
                var packet = new Dictionary<string, object>
                {
                    { "action", "read_receipt" },
                    { "to", toClientId },
                    { "messageId", messageId }
                };
                byte[] bytes = Encoding.UTF8.GetBytes(json.Serialize(packet));
                await webSocket.SendAsync(new ArraySegment<byte>(bytes), WebSocketMessageType.Text, true, CancellationToken.None);
            }
            catch { }
        }

        // =====================================================================
        // ОБРАБОТКА ВХОДЯЩЕГО СООБЩЕНИЯ
        // =====================================================================
        private void HandleIncomingWsPacket(string jsonRaw)
        {
            try
            {
                var packet = json.Deserialize<Dictionary<string, object>>(jsonRaw);
                if (packet == null) return;

                string action = packet.ContainsKey("action") ? packet["action"].ToString() : "";

                if (action == "registered")
                {
                    if (packet.ContainsKey("onlineClients") && packet["onlineClients"] is System.Collections.ArrayList)
                    {
                        var list = packet["onlineClients"] as System.Collections.ArrayList;
                        onlineClientIds.Clear();
                        foreach (var id in list) if (id != null) onlineClientIds.Add(id.ToString());
                        Dispatcher.Invoke(new Action(delegate
                        {
                            RenderContactList();
                            UpdateActiveChatStatus();
                        }));
                    }
                    return;
                }

                if (action == "presence")
                {
                    string pId = packet.ContainsKey("clientId") ? packet["clientId"].ToString() : "";
                    string pStatus = packet.ContainsKey("status") ? packet["status"].ToString() : "";
                    if (!string.IsNullOrEmpty(pId))
                    {
                        if (pStatus == "online") onlineClientIds.Add(pId);
                        else onlineClientIds.Remove(pId);
                        Dispatcher.Invoke(new Action(delegate
                        {
                            RenderContactList();
                            UpdateActiveChatStatus();
                        }));
                    }
                    return;
                }

                if (action == "message_read")
                {
                    string readMsgId = packet.ContainsKey("messageId") ? packet["messageId"].ToString() : "";
                    string readerId = packet.ContainsKey("readerId") ? packet["readerId"].ToString() : "";
                    if (!string.IsNullOrEmpty(readMsgId))
                    {
                        Dispatcher.Invoke(new Action(delegate
                        {
                            if (!string.IsNullOrEmpty(readerId) && messages.ContainsKey(readerId))
                            {
                                var m = messages[readerId].Find(delegate(MessageModel mm) { return mm.Id == readMsgId; });
                                if (m != null) { m.IsRead = true; SaveMessages(); }
                            }
                            else
                            {
                                foreach (var kvp in messages)
                                {
                                    var m = kvp.Value.Find(delegate(MessageModel mm) { return mm.Id == readMsgId; });
                                    if (m != null) { m.IsRead = true; SaveMessages(); break; }
                                }
                            }
                            UpdateBubbleCheckmark(readMsgId);
                        }));
                    }
                    return;
                }

                if (action == "typing")
                {
                    string fromId = packet.ContainsKey("from") && packet["from"] != null ? packet["from"].ToString() : "";
                    if (!string.IsNullOrEmpty(fromId))
                    {
                        Dispatcher.Invoke(new Action(delegate
                        {
                            HandleIncomingTyping(fromId);
                        }));
                    }
                    return;
                }

                if (action == "incoming_envelope")
                {
                    var env = packet["envelope"] as Dictionary<string, object>;
                    if (env != null)
                    {
                        string decryptedJson = NativeCrypto.DecryptEnvelope(identity.PrivateKeyB64, env);
                        var payload = json.Deserialize<Dictionary<string, object>>(decryptedJson);

                        string senderId = payload.ContainsKey("senderId") ? (payload["senderId"] != null ? payload["senderId"].ToString() : "") : "";
                        string senderPub = payload.ContainsKey("senderPublicKeyB64") && payload["senderPublicKeyB64"] != null ? payload["senderPublicKeyB64"].ToString() : null;

                        // КРИПТОГРАФИЧЕСКАЯ ПРОВЕРКА ПОДЛИННОСТИ ОТПРАВИТЕЛЯ (Anti-Spoofing & Zero-Trust Authenticity)
                        if (string.IsNullOrEmpty(senderId) || string.IsNullOrEmpty(senderPub))
                        {
                            return; // Отклоняем конверт без senderId или открытого ключа
                        }

                        string expectedId;
                        try
                        {
                            byte[] pubBytes = Convert.FromBase64String(senderPub);
                            using (var sha = SHA256.Create())
                            {
                                byte[] hash = sha.ComputeHash(pubBytes);
                                var sb = new StringBuilder();
                                foreach (byte b in hash) sb.Append(b.ToString("x2"));
                                expectedId = sb.ToString();
                            }
                        }
                        catch
                        {
                            return; // Некорректный Base64 открытого ключа
                        }

                        if (!string.Equals(senderId, expectedId, StringComparison.OrdinalIgnoreCase))
                        {
                            // Критическая ошибка: senderId подделан! Отбрасываем
                            return;
                        }

                        // Защита от MITM / подмены открытого ключа для уже известного контакта
                        var knownContact = contacts.Find(delegate(ContactModel c) { return c.Id == senderId; });
                        if (knownContact != null && !string.IsNullOrEmpty(knownContact.PublicKeyB64))
                        {
                            if (!string.Equals(knownContact.PublicKeyB64, senderPub, StringComparison.Ordinal))
                            {
                                return; // Попытка подмены ключа! Отбрасываем
                            }
                        }

                        string pType = payload.ContainsKey("type") && payload["type"] != null ? payload["type"].ToString() : null;
                        string targetGroupId = payload.ContainsKey("groupId") && payload["groupId"] != null ? payload["groupId"].ToString() : null;
                        string chatKey = !string.IsNullOrEmpty(targetGroupId) ? targetGroupId : senderId;

                        if (pType == "delete_message")
                        {
                            string targetId = payload.ContainsKey("targetMessageId") && payload["targetMessageId"] != null ? payload["targetMessageId"].ToString() : null;
                            if (!string.IsNullOrEmpty(targetId))
                            {
                                Dispatcher.Invoke(new Action(delegate
                                {
                                    if (messages.ContainsKey(chatKey))
                                    {
                                        var m = messages[chatKey].Find(delegate(MessageModel mm) { return mm.Id == targetId; });
                                        if (m != null)
                                        {
                                            messages[chatKey].Remove(m);
                                            SaveMessages();
                                        }
                                    }
                                    if (activeContact != null && activeContact.Id == chatKey)
                                    {
                                        UIElement toRemove = null;
                                        foreach (UIElement child in panelMessages.Children)
                                        {
                                            var g = child as Grid;
                                            if (g != null && (string)g.Tag == targetId) { toRemove = child; break; }
                                        }
                                        if (toRemove != null) panelMessages.Children.Remove(toRemove);
                                    }
                                    RenderContactList();
                                }));
                            }
                            return;
                        }

                        if (pType == "edit_message")
                        {
                            string targetId = payload.ContainsKey("targetMessageId") && payload["targetMessageId"] != null ? payload["targetMessageId"].ToString() : null;
                            string newTxt = payload.ContainsKey("newText") && payload["newText"] != null ? payload["newText"].ToString() : "";
                            if (!string.IsNullOrEmpty(targetId))
                            {
                                Dispatcher.Invoke(new Action(delegate
                                {
                                    if (messages.ContainsKey(chatKey))
                                    {
                                        var m = messages[chatKey].Find(delegate(MessageModel mm) { return mm.Id == targetId; });
                                        if (m != null)
                                        {
                                            m.Text = newTxt;
                                            m.IsEdited = true;
                                            SaveMessages();
                                        }
                                    }
                                    if (activeContact != null && activeContact.Id == chatKey)
                                    {
                                        UpdateBubbleText(targetId, newTxt);
                                    }
                                    RenderContactList();
                                }));
                            }
                            return;
                        }

                        if (pType == "reaction")
                        {
                            string targetId = payload.ContainsKey("targetMessageId") && payload["targetMessageId"] != null ? payload["targetMessageId"].ToString() : null;
                            string emoji = payload.ContainsKey("emoji") && payload["emoji"] != null ? payload["emoji"].ToString() : null;
                            if (!string.IsNullOrEmpty(targetId) && !string.IsNullOrEmpty(emoji))
                            {
                                Dispatcher.Invoke(new Action(delegate
                                {
                                    if (messages.ContainsKey(chatKey))
                                    {
                                        var m = messages[chatKey].Find(delegate(MessageModel mm) { return mm.Id == targetId; });
                                        if (m != null)
                                        {
                                            if (m.Reactions == null) m.Reactions = new Dictionary<string, List<string>>();
                                            if (!m.Reactions.ContainsKey(emoji)) m.Reactions[emoji] = new List<string>();
                                            if (m.Reactions[emoji].Contains(senderId))
                                            {
                                                m.Reactions[emoji].Remove(senderId);
                                                if (m.Reactions[emoji].Count == 0) m.Reactions.Remove(emoji);
                                            }
                                            else
                                            {
                                                m.Reactions[emoji].Add(senderId);
                                            }
                                            SaveMessages();
                                        }
                                    }
                                    if (activeContact != null && activeContact.Id == chatKey)
                                    {
                                        RefreshBubbleReactions(targetId);
                                    }
                                }));
                            }
                            return;
                        }

                        if (pType == "pin_message")
                        {
                            bool unpin = payload.ContainsKey("unpin") && payload["unpin"] != null && Convert.ToBoolean(payload["unpin"]);
                            string targetId = payload.ContainsKey("targetMessageId") && payload["targetMessageId"] != null ? payload["targetMessageId"].ToString() : null;
                            Dispatcher.Invoke(new Action(delegate
                            {
                                if (unpin)
                                {
                                    pinnedMessages.Remove(chatKey);
                                }
                                else if (!string.IsNullOrEmpty(targetId))
                                {
                                    pinnedMessages[chatKey] = targetId;
                                }
                                SavePinnedMessages();
                                if (activeContact != null && activeContact.Id == chatKey)
                                {
                                    UpdatePinnedBanner(chatKey);
                                }
                            }));
                            return;
                        }

                        string gName = payload.ContainsKey("groupName") && payload["groupName"] != null ? payload["groupName"].ToString() : "Групповой чат";
                        string senderName = payload.ContainsKey("senderName") ? payload["senderName"].ToString() : "";
                        string text = payload.ContainsKey("text") ? (payload["text"] != null ? payload["text"].ToString() : "") : "";
                        string photo = payload.ContainsKey("photo") ? (payload["photo"] != null ? payload["photo"].ToString() : null) : null;
                        string voice = null;
                        int voiceDur = 0;
                        if (payload.ContainsKey("voice") && payload["voice"] != null)
                        {
                            if (payload["voice"] is Dictionary<string, object>)
                            {
                                var vObj = payload["voice"] as Dictionary<string, object>;
                                voice = vObj.ContainsKey("data") && vObj["data"] != null ? vObj["data"].ToString() : null;
                                voiceDur = vObj.ContainsKey("duration") && vObj["duration"] != null ? Convert.ToInt32(vObj["duration"]) : 0;
                            }
                            else
                            {
                                voice = payload["voice"].ToString();
                                voiceDur = payload.ContainsKey("voiceDuration") ? Convert.ToInt32(payload["voiceDuration"]) : 0;
                            }
                        }

                        // Поддержка как фото, так и любых файлов (PDF, ZIP, DOCX, TXT и др.)
                        string fName = null;
                        long fSize = 0;
                        string fType = null;
                        string fB64 = null;

                        if (payload.ContainsKey("file") && payload["file"] != null)
                        {
                            if (payload["file"] is Dictionary<string, object>)
                            {
                                var fObj = payload["file"] as Dictionary<string, object>;
                                if (fObj.ContainsKey("name") && fObj["name"] != null) fName = fObj["name"].ToString();
                                if (fObj.ContainsKey("type") && fObj["type"] != null) fType = fObj["type"].ToString();
                                if (fObj.ContainsKey("size") && fObj["size"] != null)
                                {
                                    try { fSize = Convert.ToInt64(fObj["size"]); } catch { }
                                }
                                if (fObj.ContainsKey("data") && fObj["data"] != null)
                                {
                                    string d = fObj["data"].ToString();
                                    if ((!string.IsNullOrEmpty(fType) && fType.StartsWith("image/")) || 
                                        (fName != null && (fName.EndsWith(".jpg", StringComparison.OrdinalIgnoreCase) || 
                                                           fName.EndsWith(".png", StringComparison.OrdinalIgnoreCase) || 
                                                           fName.EndsWith(".webp", StringComparison.OrdinalIgnoreCase) || 
                                                           fName.EndsWith(".jpeg", StringComparison.OrdinalIgnoreCase))))
                                    {
                                        photo = d;
                                    }
                                    else
                                    {
                                        fB64 = d;
                                    }
                                }
                            }
                        }

                        // Нормализация времени (Unix Timestamp в мс)
                        long msgTimestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                        if (payload.ContainsKey("timestamp") && payload["timestamp"] != null)
                        {
                            try { msgTimestamp = Convert.ToInt64(payload["timestamp"]); } catch { }
                        }

                        int destruct = payload.ContainsKey("destructSeconds") ? Convert.ToInt32(payload["destructSeconds"]) : 0;

                        Dispatcher.Invoke(new Action(delegate
                        {
                            ContactModel existing = null;
                            string lastSummary = !string.IsNullOrEmpty(text) ? text : (!string.IsNullOrEmpty(voice) ? "🎤 Голосовое" : (!string.IsNullOrEmpty(photo) ? "📷 Фотография" : (!string.IsNullOrEmpty(fName) ? ("📄 " + fName) : "Вложение")));

                            if (!string.IsNullOrEmpty(targetGroupId))
                            {
                                existing = contacts.Find(delegate(ContactModel c) { return c.Id == targetGroupId; });
                                if (existing == null)
                                {
                                    existing = new ContactModel
                                    {
                                        Id = targetGroupId,
                                        Name = gName,
                                        IsGroup = true,
                                        MemberIds = new List<string> { senderId, identity.Id },
                                        PublicKeyB64 = "",
                                        LastMessage = lastSummary,
                                        LastTime = DateTime.Now.ToString("HH:mm")
                                    };
                                    contacts.Add(existing);
                                    SaveContacts();
                                }
                                else
                                {
                                    if (existing.MemberIds == null) existing.MemberIds = new List<string>();
                                    if (!existing.MemberIds.Contains(senderId)) existing.MemberIds.Add(senderId);
                                }

                                // Также сохраняем контакт отправителя, если его еще нет
                                var senderContact = contacts.Find(delegate(ContactModel c) { return c.Id == senderId; });
                                if (senderContact == null && payload.ContainsKey("senderPublicKeyB64"))
                                {
                                    string dispName = !string.IsNullOrEmpty(senderName) ? senderName : ("Участник (" + senderId.Substring(0, 6) + ")");
                                    contacts.Add(new ContactModel
                                    {
                                        Id = senderId,
                                        Name = dispName,
                                        PublicKeyB64 = payload["senderPublicKeyB64"].ToString(),
                                        LastMessage = "Участник группы",
                                        LastTime = DateTime.Now.ToString("HH:mm")
                                    });
                                    SaveContacts();
                                }
                            }
                            else
                            {
                                existing = contacts.Find(delegate(ContactModel c) { return c.Id == senderId; });
                                if (existing == null && payload.ContainsKey("senderPublicKeyB64"))
                                {
                                    string dispName = !string.IsNullOrEmpty(senderName) ? senderName : ("Собеседник (" + senderId.Substring(0, 6) + ")");
                                    existing = new ContactModel
                                    {
                                        Id = senderId,
                                        Name = dispName,
                                        PublicKeyB64 = payload["senderPublicKeyB64"].ToString(),
                                        LastMessage = lastSummary,
                                        LastTime = DateTime.Now.ToString("HH:mm")
                                    };
                                    contacts.Add(existing);
                                    SaveContacts();
                                }
                            }

                            if (existing != null)
                            {
                                existing.LastMessage = (!string.IsNullOrEmpty(targetGroupId) && !string.IsNullOrEmpty(senderName) ? (senderName + ": ") : "") + lastSummary;
                                existing.LastTime = DateTime.Now.ToString("HH:mm");
                            }

                            if (!messages.ContainsKey(chatKey)) messages[chatKey] = new List<MessageModel>();

                            string cipherFull = env["ciphertext"].ToString();
                            string cipherPreview = cipherFull.Length > 48 ? (cipherFull.Substring(0, 48) + "...") : cipherFull;

                            string rId = payload.ContainsKey("replyToId") && payload["replyToId"] != null ? payload["replyToId"].ToString() : null;
                            string rText = payload.ContainsKey("replyPreviewText") && payload["replyPreviewText"] != null ? payload["replyPreviewText"].ToString() : null;
                            string rName = payload.ContainsKey("replySenderName") && payload["replySenderName"] != null ? payload["replySenderName"].ToString() : null;
                            string incomingMsgId = payload.ContainsKey("id") && payload["id"] != null ? payload["id"].ToString() : ("msg_" + msgTimestamp + "_" + Guid.NewGuid().ToString("N").Substring(0, 6));

                            bool isCurrentChat = (activeContact != null && activeContact.Id == chatKey);

                            var newMsg = new MessageModel
                            {
                                Id = incomingMsgId,
                                FromMe = false,
                                SenderId = senderId,
                                SenderName = senderName,
                                Text = text,
                                PhotoB64 = photo,
                                VoiceB64 = voice,
                                VoiceDuration = voiceDur,
                                FileName = fName,
                                FileSize = fSize,
                                FileType = fType,
                                FileB64 = fB64,
                                Timestamp = msgTimestamp,
                                DestructSeconds = destruct,
                                CipherDebug = cipherPreview,
                                IsRead = isCurrentChat,
                                ReplyToId = rId,
                                ReplyPreviewText = rText,
                                ReplySenderName = rName,
                                ForwardedFrom = payload.ContainsKey("forwardedFrom") && payload["forwardedFrom"] != null ? payload["forwardedFrom"].ToString() : null
                            };

                            messages[chatKey].Add(newMsg);
                            SaveMessages();

                            if (isCurrentChat)
                            {
                                if (string.IsNullOrEmpty(targetGroupId))
                                {
                                    SendReadReceipt(senderId, incomingMsgId);
                                }
                            }
                            else
                            {
                                if (existing != null)
                                {
                                    existing.UnreadCount++;
                                    SaveContacts();
                                }
                            }

                            RenderContactList();

                            // Если активный контакт еще не был выбран (как у Алисы при старте),
                            // мы АВТОМАТИЧЕСКИ выбираем открывающий диалог!
                            if (activeContact == null)
                            {
                                if (existing != null)
                                {
                                    SelectContact(existing);
                                }
                            }
                            else if (activeContact.Id == chatKey)
                            {
                                AppendMessageBubble(newMsg);
                                scrollMessages.ScrollToEnd();
                            }
                            else
                            {
                                string preview = !string.IsNullOrEmpty(text) ? text : (!string.IsNullOrEmpty(fName) ? fName : "Вложение");
                                ShowToast("Новое сообщение в " + (existing != null ? existing.Name : "чате") + ": " + preview, ToastType.Info);
                            }

                            NativeAudio.PlayReceiveSound();

                            if (destruct > 0)
                            {
                                StartSelfDestruct(newMsg, chatKey);
                            }
                        }));
                    }
                }
            }
            catch { }
        }

        // =====================================================================
        // ОТПРАВКА СООБЩЕНИЙ
        // =====================================================================
        private async Task SendEnvelopeToContactAsync(ContactModel contact, Dictionary<string, object> payload)
        {
            if (webSocket == null || webSocket.State != WebSocketState.Open || contact == null || string.IsNullOrEmpty(contact.PublicKeyB64)) return;
            try
            {
                string pJson = json.Serialize(payload);
                var env = NativeCrypto.EncryptEnvelope(contact.PublicKeyB64, pJson);
                var sendPacket = new Dictionary<string, object>
                {
                    { "action", "send_envelope" },
                    { "to", contact.Id },
                    { "envelope", env }
                };
                byte[] bytes = Encoding.UTF8.GetBytes(json.Serialize(sendPacket));
                await webSocket.SendAsync(new ArraySegment<byte>(bytes), WebSocketMessageType.Text, true, CancellationToken.None);
            }
            catch { }
        }

        private async Task FanOutEnvelopeAsync(ContactModel groupContact, Dictionary<string, object> payload)
        {
            if (groupContact == null || groupContact.MemberIds == null) return;
            foreach (var memberId in groupContact.MemberIds)
            {
                if (memberId == identity.Id) continue;
                var memberContact = contacts.Find(delegate(ContactModel c) { return c.Id == memberId; });
                if (memberContact != null && !string.IsNullOrEmpty(memberContact.PublicKeyB64))
                {
                    await SendEnvelopeToContactAsync(memberContact, payload);
                }
            }
        }

        private async void DeleteMessageForEveryone(MessageModel msg)
        {
            if (activeContact == null) return;
            string chatId = activeContact.Id;

            if (messages.ContainsKey(chatId))
            {
                messages[chatId].Remove(msg);
                SaveMessages();
            }

            UIElement toRemove = null;
            foreach (UIElement child in panelMessages.Children)
            {
                var grid = child as Grid;
                if (grid != null && (string)grid.Tag == msg.Id)
                {
                    toRemove = child;
                    break;
                }
            }
            if (toRemove != null) panelMessages.Children.Remove(toRemove);

            var delPayload = new Dictionary<string, object>
            {
                { "type", "delete_message" },
                { "targetMessageId", msg.Id },
                { "senderId", identity.Id },
                { "senderPublicKeyB64", identity.PublicKeyB64 },
                { "timestamp", DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() }
            };

            if (activeContact.IsGroup)
            {
                delPayload["groupId"] = activeContact.Id;
                await FanOutEnvelopeAsync(activeContact, delPayload);
            }
            else
            {
                await SendEnvelopeToContactAsync(activeContact, delPayload);
            }

            ShowToast("Сообщение удалено у всех", ToastType.Info);
            RenderContactList();
        }

        private async void SendMessageFromInput()
        {
            if (activeContact == null)
            {
                ShowToast("Пожалуйста, выберите чат из списка слева", ToastType.Warning);
                return;
            }

            string text = txtInput.Text.Trim();

            // Если мы в режиме редактирования сообщения:
            if (editingMessage != null)
            {
                if (string.IsNullOrEmpty(text))
                {
                    ShowToast("Текст сообщения не может быть пустым", ToastType.Warning);
                    return;
                }
                editingMessage.Text = text;
                editingMessage.IsEdited = true;
                SaveMessages();
                UpdateBubbleText(editingMessage.Id, text);

                var editPayload = new Dictionary<string, object>
                {
                    { "type", "edit_message" },
                    { "targetMessageId", editingMessage.Id },
                    { "newText", text },
                    { "senderId", identity.Id },
                    { "senderPublicKeyB64", identity.PublicKeyB64 },
                    { "timestamp", DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() }
                };

                if (activeContact.IsGroup)
                {
                    editPayload["groupId"] = activeContact.Id;
                    await FanOutEnvelopeAsync(activeContact, editPayload);
                }
                else
                {
                    await SendEnvelopeToContactAsync(activeContact, editPayload);
                }

                txtInput.Text = "";
                ClearEditMode();
                RenderContactList();
                return;
            }

            if (string.IsNullOrEmpty(text) && string.IsNullOrEmpty(attachedPhotoB64) && attachedFileBytes == null)
            {
                return;
            }

            if (webSocket == null || webSocket.State != WebSocketState.Open)
            {
                ShowToast("Нет подключения к слепому релей-серверу", ToastType.Error);
                return;
            }

            int destruct = currentDestructSeconds;
            long nowMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            string msgId = "msg_" + nowMs + "_" + Guid.NewGuid().ToString("N").Substring(0, 6);

            object fileObj = null;
            if (!string.IsNullOrEmpty(attachedPhotoB64))
            {
                fileObj = new Dictionary<string, object>
                {
                    { "name", !string.IsNullOrEmpty(attachedPhotoName) ? attachedPhotoName : "photo.jpg" },
                    { "type", "image/jpeg" },
                    { "size", attachedPhotoB64.Length },
                    { "data", "data:image/jpeg;base64," + attachedPhotoB64 }
                };
            }
            else if (attachedFileBytes != null)
            {
                string fileB64 = Convert.ToBase64String(attachedFileBytes);
                string fMime = !string.IsNullOrEmpty(attachedFileType) ? attachedFileType : "application/octet-stream";
                fileObj = new Dictionary<string, object>
                {
                    { "name", attachedFileName },
                    { "type", fMime },
                    { "size", attachedFileSize },
                    { "data", "data:" + fMime + ";base64," + fileB64 }
                };
            }

            var payload = new Dictionary<string, object>
            {
                { "id", msgId },
                { "text", text },
                { "photo", attachedPhotoB64 },
                { "file", fileObj },
                { "voice", null },
                { "voiceDuration", 0 },
                { "senderId", identity.Id },
                { "senderName", identity.Name },
                { "senderPublicKeyB64", identity.PublicKeyB64 },
                { "timestamp", nowMs },
                { "destructSeconds", destruct },
                { "replyToId", replyingMessage != null ? replyingMessage.Id : null },
                { "replyPreviewText", replyingMessage != null ? GetMessageSummary(replyingMessage) : null },
                { "replySenderName", replyingMessage != null ? (replyingMessage.FromMe ? "Вы" : activeContact.Name) : null }
            };

            string cPreview = "";
            try
            {
                if (activeContact.IsGroup)
                {
                    payload["groupId"] = activeContact.Id;
                    payload["groupName"] = activeContact.Name;
                    await FanOutEnvelopeAsync(activeContact, payload);
                    cPreview = "👥 Fan-Out [" + (activeContact.MemberIds != null ? activeContact.MemberIds.Count : 0) + " участн.]";
                }
                else
                {
                    string payloadJson = json.Serialize(payload);
                    var envelope = NativeCrypto.EncryptEnvelope(activeContact.PublicKeyB64, payloadJson);

                    var sendPacket = new Dictionary<string, object>
                    {
                        { "action", "send_envelope" },
                        { "to", activeContact.Id },
                        { "envelope", envelope }
                    };
                    byte[] bytes = Encoding.UTF8.GetBytes(json.Serialize(sendPacket));
                    await webSocket.SendAsync(new ArraySegment<byte>(bytes), WebSocketMessageType.Text, true, CancellationToken.None);

                    string cText = envelope["ciphertext"];
                    cPreview = cText.Length > 48 ? (cText.Substring(0, 48) + "...") : cText;
                }
            }
            catch (Exception ex)
            {
                ShowToast("Ошибка отправки: " + ex.Message, ToastType.Error);
                return;
            }

            var myMsg = new MessageModel
            {
                Id = msgId,
                FromMe = true,
                Text = text,
                PhotoB64 = attachedPhotoB64,
                VoiceB64 = null,
                VoiceDuration = 0,
                FileName = attachedFileName,
                FileSize = attachedFileSize,
                FileType = attachedFileType,
                FileB64 = attachedFileBytes != null ? Convert.ToBase64String(attachedFileBytes) : null,
                Timestamp = nowMs,
                DestructSeconds = destruct,
                CipherDebug = cPreview,
                IsRead = false,
                ReplyToId = replyingMessage != null ? replyingMessage.Id : null,
                ReplyPreviewText = replyingMessage != null ? GetMessageSummary(replyingMessage) : null,
                ReplySenderName = replyingMessage != null ? (replyingMessage.FromMe ? "Вы" : activeContact.Name) : null
            };

            if (!messages.ContainsKey(activeContact.Id)) messages[activeContact.Id] = new List<MessageModel>();
            messages[activeContact.Id].Add(myMsg);
            SaveMessages();

            string lastSummary = "Вы: ";
            if (!string.IsNullOrEmpty(text)) lastSummary += text;
            else if (!string.IsNullOrEmpty(attachedPhotoB64)) lastSummary += "📷 Фотография";
            else if (attachedFileBytes != null) lastSummary += "📄 " + attachedFileName;
            else lastSummary += "Вложение";

            activeContact.LastMessage = lastSummary;
            activeContact.LastTime = DateTime.Now.ToString("HH:mm");

            txtInput.Text = "";
            chatDrafts.Remove(activeContact.Id);
            ClearAttachedPhoto();
            ClearReply();

            AppendMessageBubble(myMsg);
            scrollMessages.ScrollToEnd();
            RenderContactList();

            NativeAudio.PlaySendSound();

            if (destruct > 0)
            {
                StartSelfDestruct(myMsg, activeContact.Id);
            }
        }

        private async void SendVoiceMessage(byte[] wavBytes, int duration)
        {
            if (activeContact == null || wavBytes == null) return;

            string voiceB64 = Convert.ToBase64String(wavBytes);
            int destruct = currentDestructSeconds;
            long nowMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            string msgId = "msg_" + nowMs + "_" + Guid.NewGuid().ToString("N").Substring(0, 6);

            var payload = new Dictionary<string, object>
            {
                { "id", msgId },
                { "text", "" },
                { "photo", null },
                { "file", null },
                { "voice", new Dictionary<string, object> {
                    { "data", "data:audio/wav;base64," + voiceB64 },
                    { "duration", duration }
                }},
                { "voiceDuration", duration },
                { "senderId", identity.Id },
                { "senderName", identity.Name },
                { "senderPublicKeyB64", identity.PublicKeyB64 },
                { "timestamp", nowMs },
                { "destructSeconds", destruct },
                { "replyToId", replyingMessage != null ? replyingMessage.Id : null },
                { "replyPreviewText", replyingMessage != null ? GetMessageSummary(replyingMessage) : null },
                { "replySenderName", replyingMessage != null ? (replyingMessage.FromMe ? "Вы" : activeContact.Name) : null }
            };

            string cPreview = "";
            try
            {
                if (activeContact.IsGroup)
                {
                    payload["groupId"] = activeContact.Id;
                    payload["groupName"] = activeContact.Name;
                    await FanOutEnvelopeAsync(activeContact, payload);
                    cPreview = "👥 Fan-Out [" + (activeContact.MemberIds != null ? activeContact.MemberIds.Count : 0) + " участн.]";
                }
                else
                {
                    string payloadJson = json.Serialize(payload);
                    var envelope = NativeCrypto.EncryptEnvelope(activeContact.PublicKeyB64, payloadJson);

                    var sendPacket = new Dictionary<string, object>
                    {
                        { "action", "send_envelope" },
                        { "to", activeContact.Id },
                        { "envelope", envelope }
                    };
                    byte[] bytes = Encoding.UTF8.GetBytes(json.Serialize(sendPacket));
                    await webSocket.SendAsync(new ArraySegment<byte>(bytes), WebSocketMessageType.Text, true, CancellationToken.None);

                    string cText = envelope["ciphertext"];
                    cPreview = cText.Length > 48 ? (cText.Substring(0, 48) + "...") : cText;
                }
            }
            catch (Exception ex)
            {
                ShowToast("Ошибка отправки: " + ex.Message, ToastType.Error);
                return;
            }

            var myMsg = new MessageModel
            {
                Id = msgId,
                FromMe = true,
                Text = "",
                PhotoB64 = null,
                VoiceB64 = voiceB64,
                VoiceDuration = duration,
                Timestamp = nowMs,
                DestructSeconds = destruct,
                CipherDebug = cPreview,
                IsRead = false,
                ReplyToId = replyingMessage != null ? replyingMessage.Id : null,
                ReplyPreviewText = replyingMessage != null ? GetMessageSummary(replyingMessage) : null,
                ReplySenderName = replyingMessage != null ? (replyingMessage.FromMe ? "Вы" : activeContact.Name) : null
            };

            if (!messages.ContainsKey(activeContact.Id)) messages[activeContact.Id] = new List<MessageModel>();
            messages[activeContact.Id].Add(myMsg);
            SaveMessages(); // Сохраняем отправленные голосовые на диск!

            activeContact.LastMessage = "Вы: 🎤 Голосовое (" + duration + "с)";
            activeContact.LastTime = DateTime.Now.ToString("HH:mm");

            AppendMessageBubble(myMsg);
            scrollMessages.ScrollToEnd();
            RenderContactList();

            NativeAudio.PlaySendSound();

            if (destruct > 0)
            {
                StartSelfDestruct(myMsg, activeContact.Id);
            }
        }

        // =====================================================================
        // ПУЗЫРИ СООБЩЕНИЙ (TELEGRAM DESKTOP AESTHETIC)
        // =====================================================================
        private void AppendMessageBubble(MessageModel msg)
        {
            var row = new Grid { Margin = new Thickness(0, 4, 0, 4) };
            row.Tag = msg.Id;

            var bubble = new Border
            {
                CornerRadius = msg.FromMe ? new CornerRadius(16, 16, 4, 16) : new CornerRadius(16, 16, 16, 4),
                Background = msg.FromMe ? BrushBubbleMe : BrushBubbleOther,
                BorderBrush = msg.FromMe ? null : BrushBorderSubtle,
                BorderThickness = msg.FromMe ? new Thickness(0) : new Thickness(1),
                Padding = new Thickness(14, 10, 14, 8),
                MaxWidth = 540,
                HorizontalAlignment = msg.FromMe ? HorizontalAlignment.Right : HorizontalAlignment.Left,
                Effect = new DropShadowEffect
                {
                    Color = Colors.Black,
                    Direction = 270,
                    ShadowDepth = 3,
                    Opacity = 0.2,
                    BlurRadius = 8
                }
            };

            var bubbleStack = new StackPanel();

            // Пересланное сообщение (Telegram style)
            if (!string.IsNullOrEmpty(msg.ForwardedFrom))
            {
                var fwdTxt = new TextBlock
                {
                    Text = "Переслано от " + msg.ForwardedFrom,
                    FontStyle = FontStyles.Italic,
                    Foreground = new SolidColorBrush(Color.FromRgb(165, 180, 252)),
                    FontSize = 10.5,
                    Margin = new Thickness(0, 0, 0, 4)
                };
                bubbleStack.Children.Add(fwdTxt);
            }

            // Если это групповой чат и сообщение от другого участника — выводим его имя сверху
            if (!msg.FromMe && !string.IsNullOrEmpty(msg.SenderName) && activeContact != null && activeContact.IsGroup)
            {
                var senderHeader = new TextBlock
                {
                    Text = msg.SenderName,
                    Foreground = new SolidColorBrush(Color.FromRgb(147, 197, 253)),
                    FontSize = 11,
                    FontWeight = FontWeights.Bold,
                    Margin = new Thickness(0, 0, 0, 4)
                };
                bubbleStack.Children.Add(senderHeader);
            }

            // Если это ответ на другое сообщение — рисуем плашку цитаты (Telegram Reply)
            if (!string.IsNullOrEmpty(msg.ReplyPreviewText))
            {
                var quoteBorder = new Border
                {
                    Background = new SolidColorBrush(Color.FromArgb(28, 0, 0, 0)),
                    CornerRadius = new CornerRadius(6),
                    Padding = new Thickness(8, 4, 8, 4),
                    Margin = new Thickness(0, 0, 0, 6),
                    Cursor = Cursors.Hand
                };
                var quoteDock = new DockPanel();
                var quoteBar = new Border
                {
                    Width = 2.5,
                    Background = new SolidColorBrush(Color.FromRgb(147, 197, 253)),
                    CornerRadius = new CornerRadius(1.5),
                    Margin = new Thickness(0, 0, 8, 0)
                };
                var quoteStack = new StackPanel();
                var quoteAuthor = new TextBlock
                {
                    Text = !string.IsNullOrEmpty(msg.ReplySenderName) ? msg.ReplySenderName : "Собеседник",
                    Foreground = new SolidColorBrush(Color.FromRgb(147, 197, 253)),
                    FontSize = 11,
                    FontWeight = FontWeights.Bold
                };
                var quoteSnippet = new TextBlock
                {
                    Text = msg.ReplyPreviewText,
                    Foreground = new SolidColorBrush(Color.FromArgb(210, 255, 255, 255)),
                    FontSize = 11,
                    TextTrimming = TextTrimming.CharacterEllipsis,
                    MaxWidth = 420
                };
                quoteStack.Children.Add(quoteAuthor);
                quoteStack.Children.Add(quoteSnippet);
                quoteDock.Children.Add(quoteBar);
                quoteDock.Children.Add(quoteStack);
                quoteBorder.Child = quoteDock;

                // Клик по цитате подсвечивает оригинальное сообщение
                quoteBorder.MouseDown += delegate
                {
                    if (!string.IsNullOrEmpty(msg.ReplyToId))
                    {
                        ScrollToAndHighlightMessage(msg.ReplyToId);
                    }
                };
                bubbleStack.Children.Add(quoteBorder);
            }

            if (!string.IsNullOrEmpty(msg.Text))
            {
                var txt = new TextBlock
                {
                    Tag = "msg_text",
                    Text = msg.Text,
                    Foreground = Brushes.White,
                    FontSize = 13.5,
                    TextWrapping = TextWrapping.Wrap,
                    LineHeight = 19
                };
                bubbleStack.Children.Add(txt);
            }

            // Фотография
            if (!string.IsNullOrEmpty(msg.PhotoB64))
            {
                try
                {
                    string mime;
                    byte[] imgBytes = DecodeBase64OrDataUrl(msg.PhotoB64, out mime);
                    if (imgBytes != null && imgBytes.Length > 0)
                    {
                        var imgSource = new BitmapImage();
                        imgSource.BeginInit();
                        imgSource.StreamSource = new MemoryStream(imgBytes);
                        imgSource.EndInit();

                        var imgBorder = new Border
                        {
                            CornerRadius = new CornerRadius(10),
                            ClipToBounds = true,
                            Margin = new Thickness(0, 4, 0, 4)
                        };
                        var imgControl = new Image
                        {
                            Source = imgSource,
                            MaxHeight = 280,
                            Stretch = Stretch.Uniform,
                            Cursor = Cursors.Hand
                        };
                        imgControl.MouseDown += delegate
                        {
                            ShowPhotoViewerModal(imgSource);
                        };
                        imgBorder.Child = imgControl;
                        bubbleStack.Children.Add(imgBorder);
                    }
                }
                catch { }
            }

            // Обычный файл (документ, архив, музыка и т.д.)
            if (!string.IsNullOrEmpty(msg.FileName))
            {
                var fileCard = new Border
                {
                    Background = new SolidColorBrush(Color.FromArgb(32, 0, 0, 0)),
                    BorderBrush = new SolidColorBrush(Color.FromArgb(50, 255, 255, 255)),
                    BorderThickness = new Thickness(1),
                    CornerRadius = new CornerRadius(10),
                    Padding = new Thickness(10, 8, 10, 8),
                    Margin = new Thickness(0, 4, 0, 4)
                };
                var fileDock = new DockPanel();
                var fileIcon = new Border
                {
                    Width = 36,
                    Height = 36,
                    CornerRadius = new CornerRadius(18),
                    Background = new SolidColorBrush(Color.FromArgb(40, 79, 164, 228)),
                    Margin = new Thickness(0, 0, 10, 0)
                };
                fileIcon.Child = new TextBlock
                {
                    Text = "📄",
                    FontSize = 16,
                    HorizontalAlignment = HorizontalAlignment.Center,
                    VerticalAlignment = VerticalAlignment.Center
                };
                fileDock.Children.Add(fileIcon);

                var btnDownload = CreateTgButton("⬇ Скачать", Color.FromArgb(60, 255, 255, 255), Color.FromArgb(100, 255, 255, 255), delegate
                {
                    SaveAttachedFile(msg);
                });
                btnDownload.Padding = new Thickness(10, 4, 10, 4);
                btnDownload.VerticalAlignment = VerticalAlignment.Center;
                DockPanel.SetDock(btnDownload, Dock.Right);
                fileDock.Children.Add(btnDownload);

                var fileMeta = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
                var fNameTxt = new TextBlock
                {
                    Text = msg.FileName,
                    Foreground = Brushes.White,
                    FontWeight = FontWeights.SemiBold,
                    FontSize = 12.5,
                    TextTrimming = TextTrimming.CharacterEllipsis,
                    MaxWidth = 220
                };
                var fSizeTxt = new TextBlock
                {
                    Text = FormatBytes(msg.FileSize),
                    Foreground = new SolidColorBrush(Color.FromArgb(180, 255, 255, 255)),
                    FontSize = 11,
                    Margin = new Thickness(0, 2, 0, 0)
                };
                fileMeta.Children.Add(fNameTxt);
                fileMeta.Children.Add(fSizeTxt);
                fileDock.Children.Add(fileMeta);

                fileCard.Child = fileDock;
                bubbleStack.Children.Add(fileCard);
            }

            // Голосовое сообщение
            if (!string.IsNullOrEmpty(msg.VoiceB64))
            {
                var voicePanel = new Border
                {
                    Background = new SolidColorBrush(Color.FromArgb(30, 0, 0, 0)),
                    CornerRadius = new CornerRadius(16),
                    Padding = new Thickness(6, 4, 12, 4),
                    Margin = new Thickness(0, 4, 0, 4)
                };
                var voiceDock = new DockPanel();
                var btnPlay = CreateTgIconButton("▶", 13, Color.FromArgb(50, 255, 255, 255), Color.FromArgb(80, 255, 255, 255), delegate
                {
                    try
                    {
                        string mime;
                        byte[] wBytes = DecodeBase64OrDataUrl(msg.VoiceB64, out mime);
                        if (wBytes != null && wBytes.Length > 0)
                        {
                            string ext = ".wav";
                            if (!string.IsNullOrEmpty(mime))
                            {
                                if (mime.Contains("webm")) ext = ".webm";
                                else if (mime.Contains("ogg")) ext = ".ogg";
                                else if (mime.Contains("mp3")) ext = ".mp3";
                                else if (mime.Contains("m4a") || mime.Contains("aac")) ext = ".m4a";
                            }
                            NativeAudio.PlayAudioBytes(wBytes, ext);
                        }
                    }
                    catch { }
                });
                btnPlay.Width = 32;
                btnPlay.Height = 32;

                var durText = new TextBlock
                {
                    Text = "🎤 (" + msg.VoiceDuration + " сек)",
                    Foreground = Brushes.White,
                    FontSize = 12,
                    VerticalAlignment = VerticalAlignment.Center,
                    Margin = new Thickness(10, 0, 0, 0)
                };

                var btnSpeed = new Border
                {
                    Background = new SolidColorBrush(Color.FromArgb(40, 255, 255, 255)),
                    CornerRadius = new CornerRadius(4),
                    Padding = new Thickness(6, 2, 6, 2),
                    Margin = new Thickness(8, 0, 0, 0),
                    Cursor = Cursors.Hand,
                    VerticalAlignment = VerticalAlignment.Center,
                    ToolTip = "Скорость воспроизведения"
                };
                var txtSpeed = new TextBlock { Text = currentAudioSpeed.ToString("0.#") + "x", Foreground = Brushes.White, FontSize = 10.5, FontWeight = FontWeights.Bold };
                btnSpeed.Child = txtSpeed;
                btnSpeed.MouseDown += delegate
                {
                    if (currentAudioSpeed == 1.0) currentAudioSpeed = 1.5;
                    else if (currentAudioSpeed == 1.5) currentAudioSpeed = 2.0;
                    else currentAudioSpeed = 1.0;
                    txtSpeed.Text = currentAudioSpeed.ToString("0.#") + "x";
                    NativeAudio.SetPlaybackSpeed(currentAudioSpeed);
                };

                voiceDock.Children.Add(btnPlay);
                voiceDock.Children.Add(btnSpeed);
                voiceDock.Children.Add(durText);
                voicePanel.Child = voiceDock;
                bubbleStack.Children.Add(voicePanel);
            }

            var metaStack = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 3, 0, 0) };
            if (msg.IsEdited)
            {
                var editBadge = new TextBlock { Tag = "edited_badge", Text = "ред. ", Foreground = BrushTextMuted, FontSize = 10, FontStyle = FontStyles.Italic };
                metaStack.Children.Add(editBadge);
            }
            if (msg.DestructSeconds > 0)
            {
                var burn = new TextBlock { Text = "💥 " + msg.DestructSeconds + "с  ", Foreground = new SolidColorBrush(Color.FromRgb(251, 113, 133)), FontSize = 10, FontWeight = FontWeights.Bold };
                metaStack.Children.Add(burn);
            }
            string timeStr = FormatUnixOrTicks(msg.Timestamp).ToString("HH:mm");
            var timeTxt = new TextBlock { Text = timeStr, Foreground = msg.FromMe ? new SolidColorBrush(Color.FromArgb(170, 255, 255, 255)) : BrushTextMuted, FontSize = 10.5 };
            metaStack.Children.Add(timeTxt);
            if (msg.FromMe)
            {
                var check = new TextBlock
                {
                    Tag = "check_" + msg.Id,
                    Text = msg.IsRead ? " ✓✓" : " ✓",
                    Foreground = new SolidColorBrush(msg.IsRead ? Color.FromRgb(79, 164, 228) : Color.FromArgb(170, 255, 255, 255)),
                    FontSize = 10.5
                };
                metaStack.Children.Add(check);
            }
            bubbleStack.Children.Add(metaStack);

            var btnCipher = new TextBlock
            {
                Text = "Показать E2EE конверт",
                Foreground = new SolidColorBrush(Color.FromRgb(6, 182, 212)),
                FontSize = 10,
                Cursor = Cursors.Hand,
                Margin = new Thickness(0, 4, 0, 0),
                Opacity = 0.8
            };
            var boxCipher = new Border
            {
                Background = new SolidColorBrush(Color.FromArgb(120, 0, 0, 0)),
                Padding = new Thickness(8),
                CornerRadius = new CornerRadius(6),
                Margin = new Thickness(0, 4, 0, 0),
                BorderBrush = new SolidColorBrush(Color.FromArgb(40, 6, 182, 212)),
                BorderThickness = new Thickness(1),
                Visibility = Visibility.Collapsed
            };
            boxCipher.Child = new TextBlock { Text = "Сервер передал шум: [" + msg.CipherDebug + "]", Foreground = new SolidColorBrush(Color.FromRgb(147, 197, 253)), FontSize = 9.5, TextWrapping = TextWrapping.Wrap, FontFamily = new FontFamily("Consolas, Courier New") };
            btnCipher.MouseDown += delegate
            {
                boxCipher.Visibility = (boxCipher.Visibility == Visibility.Visible) ? Visibility.Collapsed : Visibility.Visible;
            };
            bubbleStack.Children.Add(btnCipher);
            bubbleStack.Children.Add(boxCipher);

            UpdateReactionsWrap(bubbleStack, msg);

            bubble.Child = bubbleStack;

            // Контекстное меню пузыря
            var cm = new ContextMenu();

            var miReactions = new MenuItem { Header = "❤️ Реакции" };
            string[] emList = new string[] { "👍", "❤️", "🔥", "👏", "😂", "😮" };
            foreach (var em in emList)
            {
                string curEm = em;
                var miEm = new MenuItem { Header = curEm };
                miEm.Click += delegate { ToggleReaction(msg, curEm); };
                miReactions.Items.Add(miEm);
            }
            cm.Items.Add(miReactions);

            var miReply = new MenuItem { Header = "↩ Ответить" };
            miReply.Click += delegate { StartReply(msg); };
            cm.Items.Add(miReply);

            bool isCurPinned = activeContact != null && pinnedMessages.ContainsKey(activeContact.Id) && pinnedMessages[activeContact.Id] == msg.Id;
            var miPin = new MenuItem { Header = isCurPinned ? "📌 Открепить" : "📌 Закрепить" };
            miPin.Click += delegate
            {
                if (isCurPinned) UnpinMessage(activeContact.Id);
                else PinMessage(msg);
            };
            cm.Items.Add(miPin);

            var miForward = new MenuItem { Header = "➡️ Переслать" };
            miForward.Click += delegate { ShowForwardDialog(msg); };
            cm.Items.Add(miForward);

            if (!string.IsNullOrEmpty(msg.Text))
            {
                var miCopy = new MenuItem { Header = "📋 Копировать текст" };
                miCopy.Click += delegate { Clipboard.SetText(msg.Text); };
                cm.Items.Add(miCopy);

                if (msg.FromMe)
                {
                    var miEdit = new MenuItem { Header = "✏️ Редактировать" };
                    miEdit.Click += delegate { StartEditMode(msg); };
                    cm.Items.Add(miEdit);
                }
            }

            if (msg.FromMe)
            {
                var miDeleteAll = new MenuItem { Header = "💥 Удалить у всех" };
                miDeleteAll.Click += delegate { DeleteMessageForEveryone(msg); };
                cm.Items.Add(miDeleteAll);
            }

            var miDelete = new MenuItem { Header = "🗑️ Удалить у себя" };
            miDelete.Click += delegate
            {
                if (activeContact != null && messages.ContainsKey(activeContact.Id))
                {
                    messages[activeContact.Id].Remove(msg);
                    SaveMessages();
                    panelMessages.Children.Remove(row);
                }
            };
            cm.Items.Add(miDelete);
            bubble.ContextMenu = cm;

            // Двойной клик по сообщению = быстрый ответ (как в Telegram)
            bubble.MouseLeftButtonDown += delegate(object s, MouseButtonEventArgs e)
            {
                if (e.ClickCount == 2)
                {
                    StartReply(msg);
                }
            };

            row.Children.Add(bubble);
            panelMessages.Children.Add(row);
        }

        private void UpdateBubbleCheckmark(string msgId)
        {
            foreach (UIElement child in panelMessages.Children)
            {
                var grid = child as Grid;
                if (grid != null && (string)grid.Tag == msgId)
                {
                    FindAndSetCheckmark(grid);
                    break;
                }
            }
        }

        private void FindAndSetCheckmark(Visual visual)
        {
            int count = VisualTreeHelper.GetChildrenCount(visual);
            for (int i = 0; i < count; i++)
            {
                var child = VisualTreeHelper.GetChild(visual, i);
                var tb = child as TextBlock;
                if (tb != null && tb.Tag != null && tb.Tag.ToString().StartsWith("check_"))
                {
                    tb.Text = " ✓✓";
                    tb.Foreground = new SolidColorBrush(Color.FromRgb(79, 164, 228));
                    return;
                }
                var vChild = child as Visual;
                if (vChild != null)
                {
                    FindAndSetCheckmark(vChild);
                }
            }
        }

        private void SaveAttachedFile(MessageModel msg)
        {
            try
            {
                string rawData = !string.IsNullOrEmpty(msg.FileB64) ? msg.FileB64 : msg.PhotoB64;
                if (string.IsNullOrEmpty(rawData))
                {
                    ShowToast("Файл пуст или поврежден", ToastType.Error);
                    return;
                }
                string mime;
                byte[] b = DecodeBase64OrDataUrl(rawData, out mime);
                if (b == null || b.Length == 0)
                {
                    ShowToast("Не удалось декодировать файл", ToastType.Error);
                    return;
                }

                var sfd = new Microsoft.Win32.SaveFileDialog
                {
                    FileName = !string.IsNullOrEmpty(msg.FileName) ? msg.FileName : "attachment",
                    Title = "Сохранить файл из чата"
                };
                string ext = System.IO.Path.GetExtension(msg.FileName ?? "");
                if (!string.IsNullOrEmpty(ext))
                {
                    sfd.Filter = "Файл (*" + ext + ")|*" + ext + "|Все файлы (*.*)|*.*";
                }
                else
                {
                    sfd.Filter = "Все файлы (*.*)|*.*";
                }

                if (sfd.ShowDialog() == true)
                {
                    File.WriteAllBytes(sfd.FileName, b);
                    ShowToast("Файл сохранен: " + System.IO.Path.GetFileName(sfd.FileName), ToastType.Success);
                }
            }
            catch (Exception ex)
            {
                ShowToast("Ошибка сохранения: " + ex.Message, ToastType.Error);
            }
        }

        private void StartReply(MessageModel msg)
        {
            ClearEditMode();
            replyingMessage = msg;
            txtReplyName.Text = msg.FromMe ? "Вы" : (activeContact != null ? activeContact.Name : "Собеседник");
            txtReplyContent.Text = GetMessageSummary(msg);
            replyPreviewBar.Visibility = Visibility.Visible;
            txtInput.Focus();
        }

        private void ClearReply()
        {
            replyingMessage = null;
            if (replyPreviewBar != null) replyPreviewBar.Visibility = Visibility.Collapsed;
        }

        private void StartEditMode(MessageModel msg)
        {
            ClearReply();
            editingMessage = msg;
            txtEditContent.Text = msg.Text ?? "";
            editPreviewBar.Visibility = Visibility.Visible;
            txtInput.Text = msg.Text ?? "";
            txtInput.Focus();
            txtInput.SelectAll();
        }

        private void ClearEditMode()
        {
            editingMessage = null;
            if (editPreviewBar != null) editPreviewBar.Visibility = Visibility.Collapsed;
        }

        private void UpdateBubbleText(string msgId, string newText)
        {
            foreach (UIElement child in panelMessages.Children)
            {
                var grid = child as Grid;
                if (grid != null && (string)grid.Tag == msgId)
                {
                    FindAndUpdateBubbleText(grid, newText);
                    break;
                }
            }
        }

        private void FindAndUpdateBubbleText(Visual visual, string newText)
        {
            int count = VisualTreeHelper.GetChildrenCount(visual);
            for (int i = 0; i < count; i++)
            {
                var child = VisualTreeHelper.GetChild(visual, i);
                var tb = child as TextBlock;
                if (tb != null && tb.Tag != null && tb.Tag.ToString() == "msg_text")
                {
                    tb.Text = newText;
                }
                var sp = child as StackPanel;
                if (sp != null)
                {
                    bool hasEdited = false;
                    foreach (UIElement elem in sp.Children)
                    {
                        var tElem = elem as TextBlock;
                        if (tElem != null && tElem.Tag != null && tElem.Tag.ToString() == "edited_badge")
                        {
                            hasEdited = true;
                            break;
                        }
                    }
                    if (!hasEdited && sp.Children.Count >= 1 && sp.Orientation == Orientation.Horizontal && sp.HorizontalAlignment == HorizontalAlignment.Right)
                    {
                        var editBadge = new TextBlock { Tag = "edited_badge", Text = "ред. ", Foreground = BrushTextMuted, FontSize = 10, FontStyle = FontStyles.Italic };
                        sp.Children.Insert(0, editBadge);
                    }
                }
                var vChild = child as Visual;
                if (vChild != null)
                {
                    FindAndUpdateBubbleText(vChild, newText);
                }
            }
        }

        private string GetMessageSummary(MessageModel msg)
        {
            if (!string.IsNullOrEmpty(msg.Text)) return msg.Text;
            if (!string.IsNullOrEmpty(msg.PhotoB64)) return "📷 Фотография";
            if (!string.IsNullOrEmpty(msg.VoiceB64)) return "🎤 Голосовое сообщение";
            if (!string.IsNullOrEmpty(msg.FileName)) return "📄 " + msg.FileName;
            return "Сообщение";
        }

        private void ScrollToAndHighlightMessage(string msgId)
        {
            foreach (UIElement child in panelMessages.Children)
            {
                var grid = child as Grid;
                if (grid != null && (string)grid.Tag == msgId)
                {
                    grid.BringIntoView();
                    var border = grid.Children.Count > 0 ? grid.Children[0] as Border : null;
                    if (border != null)
                    {
                        var origBg = border.Background;
                        border.Background = new SolidColorBrush(Color.FromRgb(79, 115, 155));
                        var animTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(450) };
                        animTimer.Tick += delegate
                        {
                            animTimer.Stop();
                            border.Background = origBg;
                        };
                        animTimer.Start();
                    }
                    break;
                }
            }
        }

        // =====================================================================
        // РЕАКЦИИ, ЗАКРЕПЫ, ПОИСК В ЧАТЕ И ПЕРЕСЫЛКА (TELEGRAM STYLE)
        // =====================================================================
        private void UpdateReactionsWrap(StackPanel bubbleStack, MessageModel msg)
        {
            if (bubbleStack == null || msg == null) return;
            UIElement existingWrap = null;
            foreach (UIElement el in bubbleStack.Children)
            {
                var fe = el as FrameworkElement;
                if (fe != null && (string)fe.Tag == "reactions_wrap")
                {
                    existingWrap = el;
                    break;
                }
            }
            if (existingWrap != null) bubbleStack.Children.Remove(existingWrap);

            if (msg.Reactions != null && msg.Reactions.Count > 0)
            {
                var wrap = new WrapPanel { Tag = "reactions_wrap", Margin = new Thickness(0, 5, 0, 0) };
                foreach (var kvp in msg.Reactions)
                {
                    string emoji = kvp.Key;
                    var users = kvp.Value;
                    if (users == null || users.Count == 0) continue;
                    bool isMy = users.Contains(identity.Id);
                    var chip = new Border
                    {
                        Background = isMy ? new SolidColorBrush(Color.FromArgb(90, 79, 164, 228)) : new SolidColorBrush(Color.FromArgb(40, 255, 255, 255)),
                        BorderBrush = isMy ? new SolidColorBrush(Color.FromRgb(79, 164, 228)) : null,
                        BorderThickness = isMy ? new Thickness(1) : new Thickness(0),
                        CornerRadius = new CornerRadius(10),
                        Padding = new Thickness(6, 2, 8, 2),
                        Margin = new Thickness(0, 0, 4, 4),
                        Cursor = Cursors.Hand
                    };
                    var chipStack = new StackPanel { Orientation = Orientation.Horizontal };
                    chipStack.Children.Add(new TextBlock { Text = emoji, FontSize = 12 });
                    chipStack.Children.Add(new TextBlock { Text = " " + users.Count, FontSize = 10.5, Foreground = Brushes.White, Margin = new Thickness(3, 0, 0, 0) });
                    chip.Child = chipStack;
                    string curEm = emoji;
                    chip.MouseDown += delegate { ToggleReaction(msg, curEm); };
                    wrap.Children.Add(chip);
                }
                bubbleStack.Children.Add(wrap);
            }
        }

        private void RefreshBubbleReactions(string msgId)
        {
            if (activeContact == null || !messages.ContainsKey(activeContact.Id)) return;
            var msg = messages[activeContact.Id].Find(delegate(MessageModel mm) { return mm.Id == msgId; });
            if (msg == null) return;
            foreach (UIElement child in panelMessages.Children)
            {
                var grid = child as Grid;
                if (grid != null && (string)grid.Tag == msgId)
                {
                    if (grid.Children.Count > 0)
                    {
                        var bubble = grid.Children[0] as Border;
                        if (bubble != null)
                        {
                            var stack = bubble.Child as StackPanel;
                            if (stack != null)
                            {
                                UpdateReactionsWrap(stack, msg);
                            }
                        }
                    }
                    break;
                }
            }
        }

        private async void ToggleReaction(MessageModel msg, string emoji)
        {
            if (activeContact == null || msg == null) return;
            if (msg.Reactions == null) msg.Reactions = new Dictionary<string, List<string>>();
            if (!msg.Reactions.ContainsKey(emoji)) msg.Reactions[emoji] = new List<string>();

            if (msg.Reactions[emoji].Contains(identity.Id))
            {
                msg.Reactions[emoji].Remove(identity.Id);
                if (msg.Reactions[emoji].Count == 0) msg.Reactions.Remove(emoji);
            }
            else
            {
                msg.Reactions[emoji].Add(identity.Id);
            }
            SaveMessages();
            RefreshBubbleReactions(msg.Id);

            var reactionPayload = new Dictionary<string, object>
            {
                { "type", "reaction" },
                { "targetMessageId", msg.Id },
                { "emoji", emoji },
                { "senderId", identity.Id },
                { "senderPublicKeyB64", identity.PublicKeyB64 },
                { "timestamp", DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() }
            };

            if (activeContact.IsGroup)
            {
                reactionPayload["groupId"] = activeContact.Id;
                await FanOutEnvelopeAsync(activeContact, reactionPayload);
            }
            else
            {
                await SendEnvelopeToContactAsync(activeContact, reactionPayload);
            }
        }

        private async void PinMessage(MessageModel msg)
        {
            if (activeContact == null || msg == null) return;
            pinnedMessages[activeContact.Id] = msg.Id;
            SavePinnedMessages();
            UpdatePinnedBanner(activeContact.Id);

            var pinPayload = new Dictionary<string, object>
            {
                { "type", "pin_message" },
                { "targetMessageId", msg.Id },
                { "senderId", identity.Id },
                { "timestamp", DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() }
            };
            if (activeContact.IsGroup)
            {
                pinPayload["groupId"] = activeContact.Id;
                await FanOutEnvelopeAsync(activeContact, pinPayload);
            }
            else
            {
                await SendEnvelopeToContactAsync(activeContact, pinPayload);
            }
            ShowToast("Сообщение закреплено", ToastType.Success);
        }

        private async void UnpinMessage(string contactId)
        {
            if (string.IsNullOrEmpty(contactId)) return;
            pinnedMessages.Remove(contactId);
            SavePinnedMessages();
            UpdatePinnedBanner(contactId);

            var unpinPayload = new Dictionary<string, object>
            {
                { "type", "pin_message" },
                { "unpin", true },
                { "senderId", identity.Id },
                { "timestamp", DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() }
            };
            var contact = contacts.Find(delegate(ContactModel c) { return c.Id == contactId; });
            if (contact != null)
            {
                if (contact.IsGroup)
                {
                    unpinPayload["groupId"] = contact.Id;
                    await FanOutEnvelopeAsync(contact, unpinPayload);
                }
                else
                {
                    await SendEnvelopeToContactAsync(contact, unpinPayload);
                }
            }
            ShowToast("Сообщение откреплено", ToastType.Info);
        }

        private void UpdatePinnedBanner(string contactId)
        {
            if (pinnedBanner == null || txtPinnedSnippet == null) return;
            if (string.IsNullOrEmpty(contactId) || !pinnedMessages.ContainsKey(contactId) || !messages.ContainsKey(contactId))
            {
                pinnedBanner.Visibility = Visibility.Collapsed;
                return;
            }
            string pinnedId = pinnedMessages[contactId];
            var msg = messages[contactId].Find(delegate(MessageModel m) { return m.Id == pinnedId; });
            if (msg == null)
            {
                pinnedBanner.Visibility = Visibility.Collapsed;
                return;
            }
            txtPinnedSnippet.Text = GetMessageSummary(msg);
            pinnedBanner.Visibility = Visibility.Visible;
        }

        private void SavePinnedMessages()
        {
            try
            {
                string appData = System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "CipherNative");
                string pinFile = System.IO.Path.Combine(appData, "pinned_" + this.userName + ".json");
                File.WriteAllText(pinFile, json.Serialize(pinnedMessages), Encoding.UTF8);
            }
            catch { }
        }

        private void LoadPinnedMessages()
        {
            try
            {
                string appData = System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "CipherNative");
                string pinFile = System.IO.Path.Combine(appData, "pinned_" + this.userName + ".json");
                if (File.Exists(pinFile))
                {
                    var loaded = json.Deserialize<Dictionary<string, string>>(File.ReadAllText(pinFile, Encoding.UTF8));
                    if (loaded != null) pinnedMessages = loaded;
                }
            }
            catch { }
        }

        private void ToggleInChatSearch()
        {
            if (inChatSearchBar == null) return;
            if (inChatSearchBar.Visibility == Visibility.Visible)
            {
                CloseInChatSearch();
            }
            else
            {
                inChatSearchBar.Visibility = Visibility.Visible;
                if (txtInChatQuery != null)
                {
                    txtInChatQuery.Text = "";
                    txtInChatQuery.Focus();
                }
                PerformInChatSearch("");
            }
        }

        private void CloseInChatSearch()
        {
            if (inChatSearchBar != null) inChatSearchBar.Visibility = Visibility.Collapsed;
            inChatSearchResults.Clear();
            inChatSearchIndex = -1;
        }

        private void PerformInChatSearch(string query)
        {
            inChatSearchResults.Clear();
            inChatSearchIndex = -1;
            string q = (query ?? "").Trim().ToLower();
            if (string.IsNullOrEmpty(q) || activeContact == null || !messages.ContainsKey(activeContact.Id))
            {
                if (txtInChatCount != null) txtInChatCount.Text = "0 совпадений";
                return;
            }

            foreach (var m in messages[activeContact.Id])
            {
                if (!string.IsNullOrEmpty(m.Text) && m.Text.ToLower().Contains(q))
                {
                    inChatSearchResults.Add(m.Id);
                }
            }

            if (txtInChatCount != null)
            {
                txtInChatCount.Text = inChatSearchResults.Count + " совпадений";
            }

            if (inChatSearchResults.Count > 0)
            {
                NavigateInChatSearch(0);
            }
        }

        private void NavigateInChatSearch(int direction)
        {
            if (inChatSearchResults.Count == 0) return;
            if (direction == 0)
            {
                inChatSearchIndex = 0;
            }
            else
            {
                inChatSearchIndex = (inChatSearchIndex + direction + inChatSearchResults.Count) % inChatSearchResults.Count;
            }

            if (txtInChatCount != null)
            {
                txtInChatCount.Text = (inChatSearchIndex + 1) + " из " + inChatSearchResults.Count;
            }

            string targetId = inChatSearchResults[inChatSearchIndex];
            ScrollToAndHighlightMessage(targetId);
        }

        private void ShowForwardDialog(MessageModel msg)
        {
            if (msg == null || contacts == null || contacts.Count == 0) return;

            var panel = new StackPanel { Width = 380, Margin = new Thickness(20) };
            var headerRow = new DockPanel { Margin = new Thickness(0, 0, 0, 14) };
            headerRow.Children.Add(new TextBlock { Text = "Переслать сообщение", Foreground = Brushes.White, FontSize = 15, FontWeight = FontWeights.Bold });
            var btnClose = CreateTgIconButton("✕", 12, Colors.Transparent, Color.FromArgb(40, 255, 255, 255), delegate { HideModal(); });
            btnClose.HorizontalAlignment = HorizontalAlignment.Right;
            headerRow.Children.Add(btnClose);
            panel.Children.Add(headerRow);

            var previewBox = new Border
            {
                Background = new SolidColorBrush(Color.FromArgb(40, 0, 0, 0)),
                BorderBrush = BrushBorderSubtle,
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(6),
                Padding = new Thickness(10, 8, 10, 8),
                Margin = new Thickness(0, 0, 0, 14)
            };
            string summary = GetMessageSummary(msg);
            previewBox.Child = new TextBlock { Text = summary, Foreground = new SolidColorBrush(Color.FromRgb(203, 213, 225)), FontSize = 12, TextTrimming = TextTrimming.CharacterEllipsis };
            panel.Children.Add(previewBox);

            panel.Children.Add(new TextBlock { Text = "Выберите чат:", Foreground = BrushTextMuted, FontSize = 12, Margin = new Thickness(0, 0, 0, 8) });

            var contactScroll = new ScrollViewer { MaxHeight = 240, VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
            var contactStack = new StackPanel();
            foreach (var c in contacts)
            {
                var item = new Border
                {
                    Background = new SolidColorBrush(Color.FromArgb(20, 255, 255, 255)),
                    CornerRadius = new CornerRadius(8),
                    Padding = new Thickness(10, 8, 10, 8),
                    Margin = new Thickness(0, 0, 0, 6),
                    Cursor = Cursors.Hand
                };
                var itemDock = new DockPanel();
                var av = CreateAvatarCircle(c.Name, c.Id, 28);
                var nameTxt = new TextBlock { Text = c.Name, Foreground = Brushes.White, FontWeight = FontWeights.SemiBold, FontSize = 13, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(10, 0, 0, 0) };
                itemDock.Children.Add(av);
                itemDock.Children.Add(nameTxt);
                item.Child = itemDock;

                var targetContact = c;
                item.MouseDown += delegate
                {
                    HideModal();
                    ForwardMessageToContact(msg, targetContact);
                };
                contactStack.Children.Add(item);
            }
            contactScroll.Content = contactStack;
            panel.Children.Add(contactScroll);

            ShowModal(panel);
        }

        private async void ForwardMessageToContact(MessageModel origMsg, ContactModel targetContact)
        {
            if (origMsg == null || targetContact == null || webSocket == null || webSocket.State != WebSocketState.Open) return;

            string senderName = origMsg.FromMe ? "Вы" : (activeContact != null ? activeContact.Name : "Собеседник");
            long nowMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            string msgId = "msg_" + nowMs + "_" + Guid.NewGuid().ToString("N").Substring(0, 6);

            object fileObj = null;
            if (!string.IsNullOrEmpty(origMsg.PhotoB64))
            {
                fileObj = new Dictionary<string, object>
                {
                    { "name", "photo.jpg" },
                    { "type", "image/jpeg" },
                    { "size", origMsg.PhotoB64.Length },
                    { "data", "data:image/jpeg;base64," + origMsg.PhotoB64 }
                };
            }
            else if (!string.IsNullOrEmpty(origMsg.FileB64))
            {
                string fMime = !string.IsNullOrEmpty(origMsg.FileType) ? origMsg.FileType : "application/octet-stream";
                fileObj = new Dictionary<string, object>
                {
                    { "name", origMsg.FileName ?? "file" },
                    { "type", fMime },
                    { "size", origMsg.FileSize },
                    { "data", "data:" + fMime + ";base64," + origMsg.FileB64 }
                };
            }

            var payload = new Dictionary<string, object>
            {
                { "id", msgId },
                { "text", origMsg.Text ?? "" },
                { "photo", origMsg.PhotoB64 },
                { "file", fileObj },
                { "voice", origMsg.VoiceB64 },
                { "voiceDuration", origMsg.VoiceDuration },
                { "senderId", identity.Id },
                { "senderName", identity.Name },
                { "senderPublicKeyB64", identity.PublicKeyB64 },
                { "timestamp", nowMs },
                { "destructSeconds", 0 },
                { "replyToId", null },
                { "replyPreviewText", null },
                { "replySenderName", null },
                { "forwardedFrom", senderName }
            };

            if (targetContact.IsGroup)
            {
                payload["groupId"] = targetContact.Id;
                payload["groupName"] = targetContact.Name;
                await FanOutEnvelopeAsync(targetContact, payload);
            }
            else
            {
                await SendEnvelopeToContactAsync(targetContact, payload);
            }

            var newMsg = new MessageModel
            {
                Id = msgId,
                FromMe = true,
                Text = origMsg.Text ?? "",
                PhotoB64 = origMsg.PhotoB64,
                VoiceB64 = origMsg.VoiceB64,
                VoiceDuration = origMsg.VoiceDuration,
                FileName = origMsg.FileName,
                FileSize = origMsg.FileSize,
                FileType = origMsg.FileType,
                FileB64 = origMsg.FileB64,
                Timestamp = nowMs,
                DestructSeconds = 0,
                CipherDebug = "Переслано от " + senderName,
                ForwardedFrom = senderName
            };

            if (!messages.ContainsKey(targetContact.Id)) messages[targetContact.Id] = new List<MessageModel>();
            messages[targetContact.Id].Add(newMsg);
            SaveMessages();
            NativeAudio.PlaySendSound();

            SelectContact(targetContact);
            ShowToast("Сообщение переслано в " + targetContact.Name, ToastType.Success);
        }

        private void NotifyTyping()
        {
            if (activeContact == null || webSocket == null || webSocket.State != WebSocketState.Open) return;
            long now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            if (now - lastTypingSentMs < 2500) return;
            lastTypingSentMs = now;

            if (activeContact.IsGroup && activeContact.MemberIds != null)
            {
                foreach (var mId in activeContact.MemberIds)
                {
                    if (mId != identity.Id)
                    {
                        var tp = new Dictionary<string, object> { { "action", "typing" }, { "to", mId } };
                        SendRawWebSocket(json.Serialize(tp));
                    }
                }
            }
            else
            {
                var tp = new Dictionary<string, object> { { "action", "typing" }, { "to", activeContact.Id } };
                SendRawWebSocket(json.Serialize(tp));
            }
        }

        private async void SendRawWebSocket(string jsonStr)
        {
            try
            {
                if (webSocket != null && webSocket.State == WebSocketState.Open)
                {
                    byte[] bytes = Encoding.UTF8.GetBytes(jsonStr);
                    await webSocket.SendAsync(new ArraySegment<byte>(bytes), WebSocketMessageType.Text, true, CancellationToken.None);
                }
            }
            catch { }
        }

        private void HandleIncomingTyping(string fromId)
        {
            var contact = contacts.Find(delegate(ContactModel c) { return c.Id == fromId; });
            string senderName = contact != null ? contact.Name : "Собеседник";

            typingContacts.Add(fromId);
            RenderContactList();

            if (activeContact != null && (activeContact.Id == fromId || (activeContact.IsGroup && activeContact.MemberIds != null && activeContact.MemberIds.Contains(fromId))))
            {
                txtActiveStatus.Text = senderName + " печатает...";
                txtActiveStatus.Foreground = BrushAccentTg;
            }

            if (typingTimer == null)
            {
                typingTimer = new DispatcherTimer();
                typingTimer.Interval = TimeSpan.FromSeconds(3);
                typingTimer.Tick += delegate
                {
                    typingTimer.Stop();
                    typingContacts.Remove(fromId);
                    RenderContactList();
                    UpdateActiveChatStatus();
                };
            }
            else
            {
                typingTimer.Stop();
            }
            typingTimer.Start();
        }

        private void StartSelfDestruct(MessageModel msg, string contactId, int remainingSeconds = -1)
        {
            int left = (remainingSeconds > 0) ? remainingSeconds : msg.DestructSeconds;
            if (left <= 0)
            {
                if (messages.ContainsKey(contactId))
                {
                    messages[contactId].Remove(msg);
                    SaveMessages();
                }
                foreach (UIElement child in panelMessages.Children)
                {
                    var grid = child as Grid;
                    if (grid != null && (string)grid.Tag == msg.Id)
                    {
                        panelMessages.Children.Remove(grid);
                        break;
                    }
                }
                return;
            }

            var timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
            timer.Tick += delegate
            {
                left--;
                if (left <= 0)
                {
                    timer.Stop();
                    if (messages.ContainsKey(contactId))
                    {
                        messages[contactId].Remove(msg);
                        SaveMessages(); // Сохраняем удаление на диск!
                    }
                    foreach (UIElement child in panelMessages.Children)
                    {
                        var grid = child as Grid;
                        if (grid != null && (string)grid.Tag == msg.Id)
                        {
                            panelMessages.Children.Remove(grid);
                            break;
                        }
                    }
                }
            };
            timer.Start();
        }

        // =====================================================================
        // ГОЛОСОВЫЕ И ФОТО
        // =====================================================================
        private void StartVoiceRecording()
        {
            bool ok = NativeAudio.StartRecording();
            if (ok)
            {
                voiceDurationSeconds = 0;
                txtVoiceTimer.Text = "00:00";
                voiceRecordingBar.Visibility = Visibility.Visible;

                voiceTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
                voiceTimer.Tick += delegate
                {
                    voiceDurationSeconds++;
                    int m = voiceDurationSeconds / 60;
                    int sec = voiceDurationSeconds % 60;
                    txtVoiceTimer.Text = m.ToString("00") + ":" + sec.ToString("00");
                };
                voiceTimer.Start();
            }
        }

        private void StopAndSendVoiceRecording()
        {
            if (voiceTimer != null) voiceTimer.Stop();
            byte[] wav = NativeAudio.StopAndGetRecording();
            voiceRecordingBar.Visibility = Visibility.Collapsed;

            if (wav != null && wav.Length > 0)
            {
                SendVoiceMessage(wav, voiceDurationSeconds);
            }
        }

        private void CancelVoiceRecording()
        {
            if (voiceTimer != null) voiceTimer.Stop();
            NativeAudio.CancelRecording();
            voiceRecordingBar.Visibility = Visibility.Collapsed;
        }

        private void ChooseAttachmentFile()
        {
            var ofd = new Microsoft.Win32.OpenFileDialog
            {
                Filter = "Все поддерживаемые форматы|*.png;*.jpg;*.jpeg;*.webp;*.gif;*.pdf;*.zip;*.rar;*.7z;*.txt;*.docx;*.xlsx;*.mp3;*.mp4;*.wav|Изображения (*.png;*.jpg;*.jpeg;*.webp)|*.png;*.jpg;*.jpeg;*.webp|Все файлы (*.*)|*.*",
                Title = "Выберите файл или фото для сквозного шифрования"
            };
            if (ofd.ShowDialog() == true)
            {
                AttachFile(ofd.FileName);
            }
        }

        private void AttachFile(string path)
        {
            try
            {
                byte[] bytes = File.ReadAllBytes(path);
                if (bytes.Length > 25 * 1024 * 1024)
                {
                    ShowToast("Размер файла превышает 25 МБ", ToastType.Warning);
                    return;
                }

                string ext = System.IO.Path.GetExtension(path).ToLower();
                bool isImg = (ext == ".jpg" || ext == ".jpeg" || ext == ".png" || ext == ".bmp" || ext == ".webp");

                if (isImg)
                {
                    try
                    {
                        var origImg = new BitmapImage();
                        origImg.BeginInit();
                        origImg.CacheOption = BitmapCacheOption.OnLoad;
                        origImg.UriSource = new Uri(path);
                        origImg.EndInit();

                        int maxWidth = 1920;
                        int maxHeight = 1080;
                        double scale = 1.0;
                        if (origImg.PixelWidth > maxWidth || origImg.PixelHeight > maxHeight)
                        {
                            scale = Math.Min((double)maxWidth / origImg.PixelWidth, (double)maxHeight / origImg.PixelHeight);
                        }

                        var targetBmp = new TransformedBitmap(origImg, new ScaleTransform(scale, scale));
                        var enc = new JpegBitmapEncoder { QualityLevel = 85 };
                        enc.Frames.Add(BitmapFrame.Create(targetBmp));
                        using (var ms = new MemoryStream())
                        {
                            enc.Save(ms);
                            bytes = ms.ToArray();
                        }
                    }
                    catch { }

                    attachedPhotoB64 = Convert.ToBase64String(bytes);
                    attachedPhotoName = System.IO.Path.GetFileName(path);
                    attachedFileBytes = null;
                    attachedFileName = null;
                    attachedFileSize = 0;
                    attachedFileType = null;
                    txtPreviewInfo.Text = "📷 " + attachedPhotoName + " (" + FormatBytes(bytes.Length) + ")";
                    attachmentPreviewBar.Visibility = Visibility.Visible;
                    ShowToast("Фото прикреплено: " + attachedPhotoName, ToastType.Info);
                }
                else
                {
                    attachedPhotoB64 = null;
                    attachedPhotoName = null;
                    attachedFileBytes = bytes;
                    attachedFileName = System.IO.Path.GetFileName(path);
                    attachedFileSize = bytes.Length;
                    attachedFileType = GetMimeTypeFromExt(ext);
                    txtPreviewInfo.Text = "📄 " + attachedFileName + " (" + FormatBytes(bytes.Length) + ")";
                    attachmentPreviewBar.Visibility = Visibility.Visible;
                    ShowToast("Файл прикреплен: " + attachedFileName, ToastType.Info);
                }
            }
            catch (Exception ex)
            {
                ShowToast("Ошибка чтения файла: " + ex.Message, ToastType.Error);
            }
        }

        private void ClearAttachedPhoto()
        {
            attachedPhotoB64 = null;
            attachedPhotoName = null;
            attachedFileBytes = null;
            attachedFileName = null;
            attachedFileSize = 0;
            attachedFileType = null;
            attachmentPreviewBar.Visibility = Visibility.Collapsed;
        }

        private string GetMimeTypeFromExt(string ext)
        {
            switch (ext)
            {
                case ".pdf": return "application/pdf";
                case ".zip": return "application/zip";
                case ".rar": return "application/x-rar-compressed";
                case ".7z": return "application/x-7z-compressed";
                case ".txt": return "text/plain";
                case ".json": return "application/json";
                case ".docx": return "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
                case ".xlsx": return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";
                case ".mp4": return "video/mp4";
                case ".mp3": return "audio/mpeg";
                default: return "application/octet-stream";
            }
        }

        private void ToggleDestructTimer()
        {
            if (currentDestructSeconds == 0) currentDestructSeconds = 10;
            else if (currentDestructSeconds == 10) currentDestructSeconds = 30;
            else if (currentDestructSeconds == 30) currentDestructSeconds = 60;
            else if (currentDestructSeconds == 60) currentDestructSeconds = 300;
            else currentDestructSeconds = 0;

            if (currentDestructSeconds == 0)
            {
                txtDestructLabel.Text = "💥 Самоуничтожение: Выкл";
                ShowToast("Таймер самоуничтожения выключен", ToastType.Info);
            }
            else if (currentDestructSeconds < 60)
            {
                txtDestructLabel.Text = "💥 " + currentDestructSeconds + " сек";
                ShowToast("Самоуничтожение: " + currentDestructSeconds + " сек", ToastType.Warning);
            }
            else
            {
                txtDestructLabel.Text = "💥 " + (currentDestructSeconds / 60) + " мин";
                ShowToast("Самоуничтожение: " + (currentDestructSeconds / 60) + " мин", ToastType.Warning);
            }
        }

        // =====================================================================
        // КОНТАКТЫ И АВТО-СОПРЯЖЕНИЕ (АЛИСА <-> БОБ)
        // =====================================================================
        private void LoadContacts()
        {
            string appData = System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "CipherNative");
            string contactFile = System.IO.Path.Combine(appData, "contacts_" + this.userName + ".json");
            string msgFile = System.IO.Path.Combine(appData, "messages_" + this.userName + ".json");

            if (File.Exists(contactFile))
            {
                try
                {
                    string raw = File.ReadAllText(contactFile, Encoding.UTF8);
                    var loaded = json.Deserialize<List<ContactModel>>(raw);
                    if (loaded != null)
                    {
                        // Фильтруем устаревшие/поврежденные контакты с ключами не P-256 (65 байт)
                        contacts = loaded.FindAll(delegate(ContactModel c)
                        {
                            if (c.IsGroup) return true;
                            if (string.IsNullOrEmpty(c.PublicKeyB64)) return false;
                            try
                            {
                                byte[] b = Convert.FromBase64String(c.PublicKeyB64);
                                return (b.Length == 65 && b[0] == 0x04) || b.Length == 64 || (b.Length == 72 && b[0] == 0x45);
                            }
                            catch { return false; }
                        });
                    }
                }
                catch { }
            }

            if (File.Exists(msgFile))
            {
                try
                {
                    string rawMsg = File.ReadAllText(msgFile, Encoding.UTF8);
                    var loadedMsgs = json.Deserialize<Dictionary<string, List<MessageModel>>>(rawMsg);
                    if (loadedMsgs != null) messages = loadedMsgs;
                }
                catch { }
            }

            RenderContactList();

            if (contacts.Count > 0 && activeContact == null)
            {
                SelectContact(contacts[0]);
            }
        }

        private void SetupMutualPairing()
        {
            string appData = System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "CipherNative");
            string otherUser = (this.userName == "\u0410\u043B\u0438\u0441\u0430") ? "\u0411\u043E\u0431" : "\u0410\u043B\u0438\u0441\u0430";
            
            // Проверяем современный P-256 файл профиля
            string p256File = System.IO.Path.Combine(appData, "identity_p256_" + otherUser + ".json");
            string otherIdFile = p256File;

            if (File.Exists(otherIdFile))
            {
                try
                {
                    var otherId = json.Deserialize<UserIdentity>(File.ReadAllText(otherIdFile, Encoding.UTF8));
                    if (otherId != null && !string.IsNullOrEmpty(otherId.PublicKeyB64))
                    {
                        var existing = contacts.Find(delegate(ContactModel c) { return c.Id == otherId.Id; });
                        if (existing == null)
                        {
                            var newContact = new ContactModel
                            {
                                Id = otherId.Id,
                                Name = otherUser,
                                PublicKeyB64 = otherId.PublicKeyB64,
                                LastMessage = "Чат защищен E2EE",
                                LastTime = ""
                            };
                            contacts.Add(newContact);
                            SaveContacts();
                            RenderContactList();

                            if (activeContact == null)
                            {
                                SelectContact(newContact);
                            }
                        }
                    }
                }
                catch { }
            }
        }

        private void SaveContacts()
        {
            try
            {
                string appData = System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "CipherNative");
                string contactFile = System.IO.Path.Combine(appData, "contacts_" + this.userName + ".json");
                File.WriteAllText(contactFile, json.Serialize(contacts), Encoding.UTF8);
            }
            catch { }
        }

        private void SaveMessages()
        {
            try
            {
                string appData = System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "CipherNative");
                string msgFile = System.IO.Path.Combine(appData, "messages_" + this.userName + ".json");
                File.WriteAllText(msgFile, json.Serialize(messages), Encoding.UTF8);
            }
            catch { }
        }

        private void RenderContactList()
        {
            panelContacts.Children.Clear();

            string q = (txtSearch != null && !string.IsNullOrEmpty(txtSearch.Text)) ? txtSearch.Text.Trim().ToLower() : "";
            var list = string.IsNullOrEmpty(q) ? contacts : contacts.FindAll(delegate(ContactModel c) { return c.Name.ToLower().Contains(q) || c.Id.ToLower().Contains(q); });

            foreach (var cItem in list)
            {
                var contact = cItem;
                bool isSelected = (activeContact != null && activeContact.Id == contact.Id);
                bool isOnline = onlineClientIds.Contains(contact.Id);

                var card = new Border
                {
                    CornerRadius = new CornerRadius(10),
                    Background = isSelected ? new SolidColorBrush(Color.FromRgb(43, 82, 120)) : Brushes.Transparent,
                    Padding = new Thickness(10, 8, 10, 8),
                    Margin = new Thickness(0, 0, 0, 3),
                    Cursor = Cursors.Hand
                };

                if (!isSelected)
                {
                    card.MouseEnter += delegate { card.Background = new SolidColorBrush(Color.FromArgb(20, 255, 255, 255)); };
                    card.MouseLeave += delegate { if (activeContact == null || activeContact.Id != contact.Id) card.Background = Brushes.Transparent; };
                }

                var dock = new DockPanel();
                var av = CreateAvatarCircle(contact.Name, contact.Id, 44, isOnline);
                var meta = new StackPanel { Margin = new Thickness(12, 0, 0, 0), VerticalAlignment = VerticalAlignment.Center };

                var topRow = new DockPanel();
                var nameTxt = new TextBlock
                {
                    Text = contact.Name,
                    Foreground = Brushes.White,
                    FontWeight = FontWeights.SemiBold,
                    FontSize = 13.5
                };
                var timeTxt = new TextBlock
                {
                    Text = contact.LastTime ?? "",
                    Foreground = isSelected ? new SolidColorBrush(Color.FromArgb(200, 255, 255, 255)) : BrushTextMuted,
                    FontSize = 11,
                    HorizontalAlignment = HorizontalAlignment.Right
                };
                topRow.Children.Add(nameTxt);
                topRow.Children.Add(timeTxt);

                var bottomRow = new DockPanel { Margin = new Thickness(0, 3, 0, 0) };

                if (contact.UnreadCount > 0)
                {
                    var unreadBadge = new Border
                    {
                        Background = new SolidColorBrush(Color.FromRgb(79, 164, 228)),
                        CornerRadius = new CornerRadius(9),
                        Padding = new Thickness(6, 1, 6, 1),
                        HorizontalAlignment = HorizontalAlignment.Right,
                        Margin = new Thickness(6, 0, 0, 0)
                    };
                    unreadBadge.Child = new TextBlock
                    {
                        Text = contact.UnreadCount.ToString(),
                        Foreground = Brushes.White,
                        FontSize = 10.5,
                        FontWeight = FontWeights.Bold
                    };
                    DockPanel.SetDock(unreadBadge, Dock.Right);
                    bottomRow.Children.Add(unreadBadge);
                }

                string preview = string.IsNullOrEmpty(contact.LastMessage) ? "Чат защищен E2EE" : contact.LastMessage;
                Brush previewColor = isSelected ? new SolidColorBrush(Color.FromArgb(220, 255, 255, 255)) : BrushTextMuted;
                if (typingContacts.Contains(contact.Id))
                {
                    preview = "печатает...";
                    previewColor = BrushAccentTg;
                }
                else if (chatDrafts.ContainsKey(contact.Id) && !string.IsNullOrEmpty(chatDrafts[contact.Id]) && (activeContact == null || activeContact.Id != contact.Id))
                {
                    preview = "Черновик: " + chatDrafts[contact.Id];
                    previewColor = new SolidColorBrush(Color.FromRgb(244, 63, 94));
                }

                var previewTxt = new TextBlock
                {
                    Text = preview,
                    Foreground = previewColor,
                    FontSize = 12,
                    TextTrimming = TextTrimming.CharacterEllipsis
                };
                bottomRow.Children.Add(previewTxt);

                meta.Children.Add(topRow);
                meta.Children.Add(bottomRow);
                dock.Children.Add(av);
                dock.Children.Add(meta);
                card.Child = dock;

                card.MouseDown += delegate { SelectContact(contact); };
                panelContacts.Children.Add(card);
            }
        }

        private void SelectContact(ContactModel c)
        {
            if (activeContact != null && activeContact.Id != c.Id && txtInput != null)
            {
                string d = txtInput.Text;
                if (!string.IsNullOrEmpty(d)) chatDrafts[activeContact.Id] = d;
                else chatDrafts.Remove(activeContact.Id);
            }

            activeContact = c;
            txtActiveName.Text = c.Name;
            UpdateActiveChatStatus();
            emptyChatPlaceholder.Visibility = Visibility.Collapsed;
            panelMessages.Children.Clear();
            UpdatePinnedBanner(c.Id);
            CloseInChatSearch();

            if (txtInput != null)
            {
                txtInput.Text = chatDrafts.ContainsKey(c.Id) ? chatDrafts[c.Id] : "";
            }

            // Сбрасываем счетчик непрочитанных для открытого контакта
            if (c.UnreadCount > 0)
            {
                c.UnreadCount = 0;
                SaveContacts();
            }

            if (messages.ContainsKey(c.Id))
            {
                long nowMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                var toRemove = new List<MessageModel>();

                foreach (var msg in new List<MessageModel>(messages[c.Id]))
                {
                    // Проверка самоуничтожения
                    if (msg.DestructSeconds > 0)
                    {
                        long elapsedSec = (nowMs - msg.Timestamp) / 1000;
                        long remain = msg.DestructSeconds - elapsedSec;
                        if (remain <= 0)
                        {
                            toRemove.Add(msg);
                            continue;
                        }
                        else
                        {
                            StartSelfDestruct(msg, c.Id, (int)remain);
                        }
                    }

                    // Отправляем уведомление о прочтении (✓✓) собеседнику
                    if (!msg.FromMe && !msg.IsRead)
                    {
                        msg.IsRead = true;
                        SendReadReceipt(c.Id, msg.Id);
                    }

                    AppendMessageBubble(msg);
                }

                if (toRemove.Count > 0)
                {
                    foreach (var rem in toRemove) messages[c.Id].Remove(rem);
                    SaveMessages();
                }

                scrollMessages.ScrollToEnd();
            }

            RenderContactList();
            txtInput.Focus();
        }

        private void UpdateActiveChatStatus()
        {
            if (activeContact == null) return;
            if (activeContact.IsGroup)
            {
                int count = activeContact.MemberIds != null ? activeContact.MemberIds.Count : 0;
                txtActiveStatus.Text = "Группа • " + count + " участн. • P-256 ECDH Fan-Out";
                txtActiveStatus.Foreground = new SolidColorBrush(Color.FromRgb(147, 197, 253));
                if (activeAvatarContainer != null)
                {
                    activeAvatarContainer.Child = CreateAvatarCircle(activeContact.Name, activeContact.Id, 38, true);
                }
                return;
            }
            bool isOnline = onlineClientIds.Contains(activeContact.Id);
            txtActiveStatus.Text = (isOnline ? "В сети • " : "Был(а) недавно • ") + "Сквозной шифр активен • P-256 ECDH";
            txtActiveStatus.Foreground = isOnline ? new SolidColorBrush(Color.FromRgb(52, 211, 153)) : BrushTextMuted;
            if (activeAvatarContainer != null)
            {
                activeAvatarContainer.Child = CreateAvatarCircle(activeContact.Name, activeContact.Id, 38, isOnline);
            }
        }

        // =====================================================================
        // ВСПОМОГАТЕЛЬНЫЕ UI ЭЛЕМЕНТЫ
        // =====================================================================
        private Border CreateTgButton(string text, Color bg, Color hover, Action onClick)
        {
            var btn = new Border
            {
                Background = new SolidColorBrush(bg),
                CornerRadius = new CornerRadius(8),
                Padding = new Thickness(14, 8, 14, 8),
                Cursor = Cursors.Hand
            };
            var txt = new TextBlock
            {
                Text = text,
                Foreground = Brushes.White,
                FontWeight = FontWeights.SemiBold,
                FontSize = 12.5,
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center
            };
            btn.Child = txt;
            btn.MouseEnter += delegate { btn.Background = new SolidColorBrush(hover); };
            btn.MouseLeave += delegate { btn.Background = new SolidColorBrush(bg); };
            btn.MouseDown += delegate { if (onClick != null) onClick(); };
            return btn;
        }

        private Border CreateTgIconButton(string icon, double size, Color bg, Color hover, Action onClick)
        {
            var btn = new Border
            {
                Background = new SolidColorBrush(bg),
                CornerRadius = new CornerRadius(8),
                Width = 34,
                Height = 34,
                Cursor = Cursors.Hand
            };
            var txt = new TextBlock
            {
                Text = icon,
                Foreground = Brushes.White,
                FontSize = size,
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center
            };
            btn.Child = txt;
            btn.MouseEnter += delegate { btn.Background = new SolidColorBrush(hover); };
            btn.MouseLeave += delegate { btn.Background = new SolidColorBrush(bg); };
            btn.MouseDown += delegate { if (onClick != null) onClick(); };
            return btn;
        }

        private FrameworkElement CreateAvatarCircle(string name, string id, double size, bool isOnline = false)
        {
            var border = new Border
            {
                Width = size,
                Height = size,
                CornerRadius = new CornerRadius(size / 2)
            };

            Color[] palette = new Color[]
            {
                Color.FromRgb(59, 130, 246),  // Blue
                Color.FromRgb(16, 185, 129),  // Emerald
                Color.FromRgb(245, 158, 11),  // Amber
                Color.FromRgb(168, 85, 247),  // Purple
                Color.FromRgb(236, 72, 153),  // Pink
                Color.FromRgb(6, 182, 212)    // Cyan
            };

            int hash = 0;
            string key = !string.IsNullOrEmpty(name) ? name : (id ?? "U");
            foreach (char ch in key) hash = (hash * 31 + ch) & 0x7FFFFFFF;
            Color baseCol = palette[hash % palette.Length];

            border.Background = new LinearGradientBrush(
                baseCol,
                Color.FromArgb(200, baseCol.R, baseCol.G, baseCol.B),
                new Point(0, 0),
                new Point(1, 1)
            );

            string initial = !string.IsNullOrEmpty(name) ? name.Substring(0, 1).ToUpper() : "U";
            if (id != null && id.StartsWith("grp_")) initial = "👥";
            var txt = new TextBlock
            {
                Text = initial,
                Foreground = Brushes.White,
                FontWeight = FontWeights.Bold,
                FontSize = size * 0.44,
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center
            };
            border.Child = txt;

            if (!isOnline) return border;

            var grid = new Grid { Width = size, Height = size };
            grid.Children.Add(border);

            double badgeSize = Math.Max(10, size * 0.28);
            var onlineDot = new Border
            {
                Width = badgeSize,
                Height = badgeSize,
                CornerRadius = new CornerRadius(badgeSize / 2),
                Background = new SolidColorBrush(Color.FromRgb(16, 185, 129)),
                BorderBrush = new SolidColorBrush(Color.FromRgb(24, 37, 51)),
                BorderThickness = new Thickness(1.5),
                HorizontalAlignment = HorizontalAlignment.Right,
                VerticalAlignment = VerticalAlignment.Bottom
            };
            grid.Children.Add(onlineDot);
            return grid;
        }
    }
}
