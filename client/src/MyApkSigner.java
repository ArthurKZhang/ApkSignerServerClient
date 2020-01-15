
import com.android.apksig.ApkSigner;
import com.android.apksig.ServerConnection;
import com.android.apksig.SigningCertificateLineage;
import com.android.apksig.apk.MinSdkVersionException;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Command-line tool for signing APKs
 *
 * parameters for main() method: " sign  --out /output-apk-path/output.apk /input-apk-path/input.apk
 */
public class MyApkSigner {

    private static final String VERSION = "0.9";
    private static final String HELP_PAGE_GENERAL = "help.txt";
    private static final String HELP_PAGE_SIGN = "help_sign.txt";

    public static void main(String[] params) throws Exception {
        if ((params.length == 0) || ("--help".equals(params[0])) || ("-h".equals(params[0]))) {
            printUsage(HELP_PAGE_GENERAL);
            return;
        } else if ("--version".equals(params[0])) {
            System.out.println(VERSION);
            return;
        }

        String cmd = params[0];
        try {
            if ("sign".equals(cmd)) {
                sign(Arrays.copyOfRange(params, 1, params.length));
                return;
            } else {
                throw new ParameterException(
                        "Unsupported command: " + cmd + ". See --help for supported commands");
            }
        } catch (ParameterException | OptionsParser.OptionsException e) {
            System.err.println(e.getMessage());
            System.exit(1);
            return;
        }
    }

    private static void sign(String[] params) throws Exception {
        if (params.length == 0) {
            printUsage(HELP_PAGE_SIGN);
            return;
        }

        File outputApk = null;
        File inputApk = null;
        boolean verbose = false;
        boolean v1SigningEnabled = true;
        boolean v2SigningEnabled = true;
        boolean v3SigningEnabled = true;
        boolean debuggableApkPermitted = true;
        int minSdkVersion = 1;
        boolean minSdkVersionSpecified = false;
        int maxSdkVersion = Integer.MAX_VALUE;
        List<SignerParams> signers = new ArrayList<>(1);
        SignerParams signerParams = new SignerParams();
        SigningCertificateLineage lineage = null;
        List<ProviderInstallSpec> providers = new ArrayList<>();
        ProviderInstallSpec providerParams = new ProviderInstallSpec();
        OptionsParser optionsParser = new OptionsParser(params);
        String optionName;
        String optionOriginalForm = null;

        while ((optionName = optionsParser.nextOption()) != null) {
            optionOriginalForm = optionsParser.getOptionOriginalForm();

            if ("out".equals(optionName)) {
                outputApk = new File(optionsParser.getRequiredValue("Output file name"));
            }

        }
        if (!signerParams.isEmpty()) {
            signers.add(signerParams);
        }
        if (!providerParams.isEmpty()) {
            providers.add(providerParams);
        }

        if (signers.isEmpty()) {
//            throw new ParameterException("At least one signer must be specified");
        }

        params = optionsParser.getRemainingParams();

        // Input APK has not been specified via preceding parameters. The next parameter is
        // supposed to be the path to input APK.
        if (params.length < 1) {
            throw new ParameterException("Missing input APK");
        } else if (params.length > 1) {
            throw new ParameterException(
                    "Unexpected parameter(s) after input APK (" + params[1] + ")");
        }
        inputApk = new File(params[0]);

        if ((minSdkVersionSpecified) && (minSdkVersion > maxSdkVersion)) {
            throw new ParameterException(
                    "Min API Level (" + minSdkVersion + ") > max API Level (" + maxSdkVersion
                            + ")");
        }

        // Install additional JCA Providers
        for (ProviderInstallSpec providerInstallSpec : providers) {
            providerInstallSpec.installProvider();
        }

        List<ApkSigner.SignerConfig> signerConfigs = new ArrayList<>(signers.size());  //没有设置 "--next-signer" 则 size = 1

        //divide init socket
        ServerConnection.initConnection();

        //divide get v1SigBasename & certs Here
        String v1SigBasename = ServerConnection.getConnection().getV1SignBasename();
        List<X509Certificate> certificates = ServerConnection.getConnection().getCerts();
        Thread.sleep(2000);


        ApkSigner.SignerConfig signerConfig =
                new ApkSigner.SignerConfig.Builder(
                        v1SigBasename, null, certificates)
                        .build();
        signerConfigs.add(signerConfig);

        if (outputApk == null) {
            outputApk = inputApk;
        }
        File tmpOutputApk;
        if (inputApk.getCanonicalPath().equals(outputApk.getCanonicalPath())) {
            tmpOutputApk = File.createTempFile("apksigner", ".apk");
            tmpOutputApk.deleteOnExit();
        } else {
            tmpOutputApk = outputApk;
        }
        ApkSigner.Builder apkSignerBuilder =
                new ApkSigner.Builder(signerConfigs)
                        .setInputApk(inputApk)
                        .setOutputApk(tmpOutputApk)
                        .setOtherSignersSignaturesPreserved(false)  //remind 默认不保留之前的签名
                        .setV1SigningEnabled(v1SigningEnabled)
                        .setV2SigningEnabled(v2SigningEnabled)
                        .setV3SigningEnabled(false)
                        .setDebuggableApkPermitted(debuggableApkPermitted)   //remind 默认对debug包进行签名
                        .setSigningCertificateLineage(lineage);
        if (minSdkVersionSpecified) {
            apkSignerBuilder.setMinSdkVersion(minSdkVersion);
        }
        ApkSigner apkSigner = apkSignerBuilder.build();
        try {
            apkSigner.sign();
        } catch (MinSdkVersionException e) {
            String msg = e.getMessage();
            if (!msg.endsWith(".")) {
                msg += '.';
            }
            throw new MinSdkVersionException(
                    "Failed to determine APK's minimum supported platform version"
                            + ". Use --min-sdk-version to override",
                    e);
        }
        if (!tmpOutputApk.getCanonicalPath().equals(outputApk.getCanonicalPath())) {
            Files.move(
                    tmpOutputApk.toPath(), outputApk.toPath(), StandardCopyOption.REPLACE_EXISTING);
        }

        if (verbose) {
            System.out.println("Signed");
        }
    }


    private static void printUsage(String page) {
        try (BufferedReader in =
                     new BufferedReader(
                             new InputStreamReader(
                                     MyApkSigner.class.getResourceAsStream(page),
                                     StandardCharsets.UTF_8))) {
            String line;
            while ((line = in.readLine()) != null) {
                System.out.println(line);
            }
        } catch (IOException e) {
            throw new RuntimeException("Failed to read " + page + " resource");
        }
    }

    private static class ProviderInstallSpec {
        String className;
        String constructorParam;
        Integer position;

        private boolean isEmpty() {
            return (className == null) && (constructorParam == null) && (position == null);
        }

        private void installProvider() throws Exception {
            if (className == null) {
                throw new ParameterException(
                        "JCA Provider class name (--provider-class) must be specified");
            }

            Class<?> providerClass = Class.forName(className);
            if (!Provider.class.isAssignableFrom(providerClass)) {
                throw new ParameterException(
                        "JCA Provider class " + providerClass + " not subclass of "
                                + Provider.class.getName());
            }
            Provider provider;
            if (constructorParam != null) {
                // Single-arg Provider constructor
                provider =
                        (Provider) providerClass.getConstructor(String.class)
                                .newInstance(constructorParam);
            } else {
                // No-arg Provider constructor
                provider = (Provider) providerClass.getConstructor().newInstance();
            }

            if (position == null) {
                Security.addProvider(provider);
            } else {
                Security.insertProviderAt(provider, position);
            }
        }
    }

}
