package burp;

import org.spongycastle.util.Arrays;
import org.spongycastle.util.encoders.Hex;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.awt.*;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.io.PrintWriter;
import java.security.Key;
import java.util.List;

public class BurpExtender implements IBurpExtender, ITab, IProxyListener, IHttpListener {
    public PrintWriter stdout;
    public IExtensionHelpers helpers;
    public IBurpExtenderCallbacks cbs;
    public JPanel jPanelMain;
    public String secret_key;
    public String initialize_vector;
    private JPanel panel;
    private JTextField parameterAESkey;
    private JTextField parameterAESIV;

    private JTextField targeturl;
    private JTextField targetparameter;

    private JLabel lblDescription;
    private JButton jButton1;
    private JButton jButton2;
    private JComboBox<String> comboAESMode;
    private JLabel lbl3;
    private JCheckBox chckbxNewCheckBox;
    private JPanel panel_1;
    private JButton btnNewButton;
    private JTextArea textAreaPlaintext;
    private JTextArea textAreaCiphertext;
    private JButton btnNewButton_1;
    private JLabel lblPlaintext;
    private JLabel lblCiphertext;
    public Boolean isURLEncoded;
    private JLabel lbl4;
    private JComboBox<String> comboEncoding;

    public String reqURL = null;
    public String reqParameter = null;


    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {

        callbacks.setExtensionName("Killer");

        this.helpers = callbacks.getHelpers();
        this.cbs = callbacks;
        this.stdout = new PrintWriter(callbacks.getStdout(), true);

//        callbacks.registerHttpListener(this);
//        callbacks.registerProxyListener(this);

        this.stdout.println("Killer Installed");

        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {

                panel = new JPanel();
                GridBagLayout gbl_panel = new GridBagLayout();
                gbl_panel.columnWidths = new int[]{197, 400, 0};
                gbl_panel.rowHeights = new int[]{0, 0, 0, 0, 0, 0, 0, 0 ,0};
                gbl_panel.columnWeights = new double[]{1.0, 1.0, 1.0,Double.MIN_VALUE};
                gbl_panel.rowWeights = new double[]{0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, Double.MIN_VALUE};
                panel.setLayout(gbl_panel);

                lblDescription = new JLabel(
                        "<html><b>Simple AES Killer v1.0</b>\r\n<br>\r\n<br>\r\n</html>");
                lblDescription.setHorizontalAlignment(SwingConstants.LEFT);
                lblDescription.setVerticalAlignment(SwingConstants.TOP);
                GridBagConstraints gbc_lblDescription = new GridBagConstraints();
                gbc_lblDescription.fill = GridBagConstraints.HORIZONTAL;
                gbc_lblDescription.insets = new Insets(20, 20, 20, 20);
                gbc_lblDescription.gridx = 1;
                gbc_lblDescription.gridy = 0;
                panel.add(lblDescription, gbc_lblDescription);

                JLabel lbl1 = new JLabel("AES key in hex format:");
                lbl1.setHorizontalAlignment(SwingConstants.RIGHT);
                GridBagConstraints gbc_lbl1 = new GridBagConstraints();
                gbc_lbl1.anchor = GridBagConstraints.EAST;
                gbc_lbl1.insets = new Insets(0, 0, 5, 5);
                gbc_lbl1.gridx = 0;
                gbc_lbl1.gridy = 1;
                panel.add(lbl1, gbc_lbl1);

                parameterAESkey = new JTextField();
                parameterAESkey.setText("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890");
                GridBagConstraints gbc_parameterAESkey = new GridBagConstraints();
                gbc_parameterAESkey.insets = new Insets(0, 0, 5, 0);
                gbc_parameterAESkey.fill = GridBagConstraints.HORIZONTAL;
                gbc_parameterAESkey.gridx = 1;
                gbc_parameterAESkey.gridy = 1;
                panel.add(parameterAESkey, gbc_parameterAESkey);
                parameterAESkey.setColumns(10);

                JLabel lbl2 = new JLabel("IV in hex format:");
                lbl2.setHorizontalAlignment(SwingConstants.RIGHT);
                GridBagConstraints gbc_lbl2 = new GridBagConstraints();
                gbc_lbl2.insets = new Insets(0, 0, 5, 5);
                gbc_lbl2.anchor = GridBagConstraints.EAST;
                gbc_lbl2.gridx = 0;
                gbc_lbl2.gridy = 2;
                panel.add(lbl2, gbc_lbl2);

                parameterAESIV = new JTextField();
                parameterAESIV.setText("abcdef1234567890abcdef1234567890");
                parameterAESIV.setColumns(10);
                GridBagConstraints gbc_parameterAESIV = new GridBagConstraints();
                gbc_parameterAESIV.insets = new Insets(0, 0, 5, 0);
                gbc_parameterAESIV.fill = GridBagConstraints.HORIZONTAL;
                gbc_parameterAESIV.gridx = 1;
                gbc_parameterAESIV.gridy = 2;
                panel.add(parameterAESIV, gbc_parameterAESIV);

                lbl3 = new JLabel("AES Mode:");
                lbl3.setHorizontalAlignment(SwingConstants.RIGHT);
                GridBagConstraints gbc_lbl3 = new GridBagConstraints();
                gbc_lbl3.insets = new Insets(0, 0, 5, 5);
                gbc_lbl3.anchor = GridBagConstraints.EAST;
                gbc_lbl3.gridx = 0;
                gbc_lbl3.gridy = 3;
                panel.add(lbl3, gbc_lbl3);

                comboAESMode = new JComboBox();
                comboAESMode.addPropertyChangeListener(new PropertyChangeListener() {
                    public void propertyChange(PropertyChangeEvent arg0) {
                        String cmode = (String) comboAESMode.getSelectedItem();
                        if (cmode.contains("CBC")) {
                            parameterAESIV.setEditable(true);
                        } else {
                            parameterAESIV.setEditable(false);
                        }
                    }
                });
                comboAESMode.setModel(new DefaultComboBoxModel(new String[]{"AES/CBC/NoPadding", "AES/CBC/PKCS5Padding",
                        "AES/ECB/NoPadding", "AES/ECB/PKCS5Padding"}));
                comboAESMode.setSelectedIndex(1);
                GridBagConstraints gbc_comboAESMode = new GridBagConstraints();
                gbc_comboAESMode.insets = new Insets(0, 0, 5, 0);
                gbc_comboAESMode.fill = GridBagConstraints.HORIZONTAL;
                gbc_comboAESMode.gridx = 1;
                gbc_comboAESMode.gridy = 3;
                panel.add(comboAESMode, gbc_comboAESMode);


                lbl4 = new JLabel("Ciphertext encoding:");
                lbl4.setHorizontalAlignment(SwingConstants.RIGHT);
                GridBagConstraints gbc_lbl4 = new GridBagConstraints();
                gbc_lbl4.anchor = GridBagConstraints.EAST;
                gbc_lbl4.insets = new Insets(0, 0, 5, 5);
                gbc_lbl4.gridx = 0;
                gbc_lbl4.gridy = 4;
                panel.add(lbl4, gbc_lbl4);

                comboEncoding = new JComboBox();
                comboEncoding.setModel(new DefaultComboBoxModel(new String[]{"Base 64", "ASCII", "Hex"}));
                comboEncoding.setSelectedIndex(0);
                GridBagConstraints gbc_comboEncoding = new GridBagConstraints();
                gbc_comboEncoding.insets = new Insets(0, 0, 5, 0);
                gbc_comboEncoding.fill = GridBagConstraints.HORIZONTAL;
                gbc_comboEncoding.gridx = 1;
                gbc_comboEncoding.gridy = 4;
                panel.add(comboEncoding, gbc_comboEncoding);

                JLabel lbl5 = new JLabel("Target_URL");
                lbl5.setHorizontalAlignment(SwingConstants.RIGHT);
                GridBagConstraints gbc_lbl5= new GridBagConstraints();
                gbc_lbl5.insets = new Insets(0, 0, 5, 5);
                gbc_lbl5.anchor = GridBagConstraints.EAST;
                gbc_lbl5.gridx = 0;
                gbc_lbl5.gridy = 5;
                panel.add(lbl5,gbc_lbl5);

                targeturl = new JTextField();
                targeturl.setText("hsbcpayme_api");
                GridBagConstraints gbc_targeturl = new GridBagConstraints();
                gbc_targeturl.insets = new Insets(0, 0, 5, 0);
                gbc_targeturl.fill = GridBagConstraints.HORIZONTAL;
                gbc_targeturl.gridx = 1;
                gbc_targeturl.gridy = 5;

                panel.add(targeturl,gbc_targeturl);

                JLabel lbl6 = new JLabel("Target_Parameter");
                lbl5.setHorizontalAlignment(SwingConstants.RIGHT);
                GridBagConstraints gbc_lbl6= new GridBagConstraints();
                gbc_lbl6.insets = new Insets(0, 0, 5, 5);
                gbc_lbl6.anchor = GridBagConstraints.EAST;
                gbc_lbl6.gridx = 0;
                gbc_lbl6.gridy = 6;
                panel.add(lbl6,gbc_lbl6);

                targetparameter = new JTextField();
                targetparameter.setText("encData");
                GridBagConstraints gbc_targetparameter = new GridBagConstraints();
                gbc_targetparameter.insets = new Insets(0, 0, 5, 0);
                gbc_targetparameter.fill = GridBagConstraints.HORIZONTAL;
                gbc_targetparameter.gridx = 1;
                gbc_targetparameter.gridy = 6;

                panel.add(targetparameter,gbc_targetparameter);


                jButton1 = new JButton();
                jButton1.setText("Start Killer");
                jButton1.setEnabled(true);
                GridBagConstraints gbc_jButton1 = new GridBagConstraints();
                gbc_jButton1.insets = new Insets(0, 200, 15, 30);
                gbc_jButton1.gridheight = 1;
                // gbc_jButton1.fill = GridBagConstraints.BOTH;
                gbc_jButton1.gridx = 0;
                gbc_jButton1.gridy = 1;

                jButton1.addActionListener(new java.awt.event.ActionListener() {
                    public void actionPerformed(java.awt.event.ActionEvent evt) {
                        callbacks.registerProxyListener(BurpExtender.this);
//                      callbacks.registerHttpListener(BurpExtender.this);
                        JOptionPane.showMessageDialog(null, "Start Killer");
                        jButton1.setEnabled(false);
                        jButton2.setEnabled(true);
                    }
                });

                panel.add(jButton1, gbc_jButton1);

                jButton2 = new JButton();
                jButton2.setText("Stop Killer");
                jButton2.setEnabled(false);
                GridBagConstraints gbc_jButton2 = new GridBagConstraints();
                gbc_jButton2.insets = new Insets(0, 200, 5, 30);
                gbc_jButton2.gridheight = 1;
                // gbc_jButton2.fill = GridBagConstraints.BOTH;
                gbc_jButton2.gridx = 0;
                gbc_jButton2.gridy = 2;

                jButton2.addActionListener(new java.awt.event.ActionListener() {
                    public void actionPerformed(java.awt.event.ActionEvent evt) {
                        callbacks.removeProxyListener(BurpExtender.this);
                        callbacks.removeHttpListener(BurpExtender.this);
                        JOptionPane.showMessageDialog(null, "Stop Killer");
                        jButton1.setEnabled(true);
                        jButton2.setEnabled(false);
                    }
                });
                panel.add(jButton2, gbc_jButton2);

                cbs.addSuiteTab(BurpExtender.this);

            }
        });

//
    }


    @Override
    public String getTabCaption() {

        return "Killer";
    }

    @Override
    public Component getUiComponent() {

        return panel;
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    public static String byteArrayToHexString(byte[] b) {
        int len = b.length;
        String data = "";
        for (int i = 0; i < len; i++) {
            data += Integer.toHexString((b[i] >> 4) & 0xf);
            data += Integer.toHexString(b[i] & 0xf);
        }
        return data;
    }

    public String encrypt(String data) throws Exception {

        byte[] keyValue = hexStringToByteArray(parameterAESkey.getText());
        Key skeySpec = new SecretKeySpec(keyValue, "AES");

        byte[] iv = hexStringToByteArray(parameterAESIV.getText());
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        String cmode = (String) comboAESMode.getSelectedItem();

        Cipher cipher = Cipher.getInstance((String) comboAESMode.getSelectedItem());
        if (cmode.contains("CBC")) {
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, ivSpec);
        } else {
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
        }
        byte[] encVal = null;
        if (cmode.equals("AES/CBC/NoPadding")) {
            int blockSize = cipher.getBlockSize();
            int plaintextLength = data.length();
            if (plaintextLength % blockSize != 0) {
                plaintextLength = plaintextLength + (blockSize - (plaintextLength % blockSize));
            }
            byte[] plaintext = new byte[plaintextLength];
            System.arraycopy(data.getBytes(), 0, plaintext, 0, data.getBytes().length);
            encVal = cipher.doFinal(plaintext);
        } else {
            encVal = cipher.doFinal(data.getBytes());
        }
        // This wont work for http requests either output ascii hex or url encoded values
        String encryptedValue = new String(encVal, "UTF-8");

        switch (comboEncoding.getSelectedItem().toString()) {
            case "Base 64":
                encryptedValue = helpers.base64Encode(encVal);
                break;
            case "ASCII":
                encryptedValue = byteArrayToHexString(encVal);
                break;
            case "Hex":
                encryptedValue = new String(Hex.encode(encVal));
                break;
        }

        return encryptedValue;
    }

    public String decrypt(String ciphertext) throws Exception {
        if (ciphertext == null) {
            return null;
        }
        if (ciphertext.equals("")) {
            return "";
        }
        byte[] keyValue = hexStringToByteArray(parameterAESkey.getText());
        Key skeySpec = new SecretKeySpec(keyValue, "AES");
        byte[] iv = hexStringToByteArray(parameterAESIV.getText());
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        String cmode = (String) comboAESMode.getSelectedItem();

        Cipher cipher = Cipher.getInstance(cmode);
        if (cmode.contains("CBC")) {
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, ivSpec);
        } else {
            cipher.init(Cipher.DECRYPT_MODE, skeySpec);
        }

        byte[] cipherbytes = ciphertext.getBytes();

        switch (comboEncoding.getSelectedItem().toString()) {
            case "Base 64":
                cipherbytes = helpers.base64Decode(ciphertext);
                break;
            case "ASCII":
                cipherbytes = hexStringToByteArray(ciphertext);
                break;
            case "Hex":
                cipherbytes = Hex.decode(cipherbytes);
                break;
        }
        byte[] original = cipher.doFinal(cipherbytes);
        /** remove 00 character */
        if (cmode.equals("AES/CBC/NoPadding")) {
            for (int i = 0; i < original.length; i++) {
                if (original[original.length - 1 - i] == 0) {
                    continue;
                }
                original = Arrays.copyOfRange(original, 0, original.length - i);
                break;
            }
        }

        return new String(original);

    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {


        stdout.println(
                (messageIsRequest ? "HTTP request to " : "HTTP response from ") +
                        messageInfo.getHttpService() +
                        " [" + cbs.getToolName(toolFlag) + "]");

    }

    @Override
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {
        reqURL = targeturl.getText();
        reqParameter = targetparameter.getText();

        if (messageIsRequest) {
            IHttpRequestResponse messageInfo = message.getMessageInfo();
            IRequestInfo reqInfo = helpers.analyzeRequest(messageInfo);
            List headers = reqInfo.getHeaders();
            String request = new String(messageInfo.getRequest());
            String URL = new String(reqInfo.getUrl().toString());

            if (URL.contains(this.reqURL) && reqInfo.getMethod().toLowerCase().contains("post"))
            {
                String messageBody = new String(request.substring(reqInfo.getBodyOffset())).trim();

                if (URL.contains(this.reqParameter))
                {
                    String arr[] = messageBody.split(this.reqParameter);
                    messageBody = arr[1].substring(0, arr[1].length()-1);
                    this.stdout.println(String.format("Post_parameter %s", messageBody));
                }

                if (!this.reqParameter.equals("") && messageBody.contains(this.reqParameter))
                {
                    String arr[] = messageBody.split(this.reqParameter);
                    messageBody = arr[1].substring(0, arr[1].length()-1);
                    this.stdout.println(String.format("Post_parameter %s", messageBody));
                }
            }

            if (URL.contains(this.reqURL) && reqInfo.getMethod().toLowerCase().contains("get"))
            {
                List<IParameter> parameters = reqInfo.getParameters();
                for (IParameter parameter : parameters) {
                    if ((parameter.getType() == 0 || parameter.getType() == 1)) {
                        if(parameter.getName().equals(reqParameter)) {
                            try {
                                this.stdout.println(String.format("Get_parameter name: %s", parameter.getName()));
                                this.stdout.println(String.format("Get_parameter value: %s", parameter.getValue()));
                            } catch (Exception e) {
                                this.stdout.println(String.format("GEt_value error: %s", e.getMessage()));
                            }
                        }

                    }
                }
            }

        }
        // handle response
        else {

            IHttpRequestResponse messageInfo = message.getMessageInfo();
            IRequestInfo reqInfo = helpers.analyzeRequest(messageInfo);
            String URL = new String(reqInfo.getUrl().toString());
//            this.stdout.println("response Url:  " + URL);

            if (URL.contains(this.reqURL) && reqInfo.getMethod().toLowerCase().contains("get") || reqInfo.getMethod().toLowerCase().contains("post"))
            {
                IResponseInfo resInfo = helpers.analyzeResponse(messageInfo.getResponse());
                List<String> headers = resInfo.getHeaders();
                String response = new String(messageInfo.getResponse());
                String response_body = new String(response.substring(resInfo.getBodyOffset())).trim();
//                this.stdout.println("response body:  " + response_body);
                // check it's not text/html
//                for (String header : headers) {
//                    if (header.toLowerCase().contains("content-type") && header.toLowerCase().contains("text/html")) {
//                        boolean HtmlFlag = true; //迟点再处理这个逻辑，先放着
//                    }
//                }
                if ( !this.reqParameter.equals("") && response_body.contains(this.reqParameter)){
                    String arr[] = response_body.split(this.reqParameter);
                    response_body = arr[1].substring(0, arr[1].length()-1);
                    this.stdout.println(String.format("Response_parameter: %s", response_body));
                }

            }

        }

    }
}








