package wotsvisualisierung_1;

import java.io.File;
import java.io.IOException;
import javax.swing.JFileChooser;
import org.eclipse.jface.viewers.IStructuredContentProvider;
import org.eclipse.jface.viewers.ITableLabelProvider;
import org.eclipse.jface.viewers.LabelProvider;
import org.eclipse.jface.viewers.Viewer;
import org.eclipse.swt.SWT;
import org.eclipse.swt.events.ModifyEvent;
import org.eclipse.swt.events.ModifyListener;
import org.eclipse.swt.events.SelectionAdapter;
import org.eclipse.swt.events.SelectionEvent;
import org.eclipse.swt.events.SelectionListener;
import org.eclipse.swt.graphics.Image;
import org.eclipse.swt.widgets.Button;
import org.eclipse.swt.widgets.Combo;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.swt.widgets.Label;
import org.eclipse.swt.widgets.Text;
import org.eclipse.ui.ISharedImages;
import org.eclipse.ui.PlatformUI;
import org.eclipse.ui.part.ViewPart;
import org.eclipse.wb.swt.ResourceManager;

public class View extends ViewPart {
	public View() {
		setPartName("WOTS-Visualisierung");
	}
	public static final String ID = "asdf.view";
	
	
	public Text txt_message;
	private Text txt_MessageSize;
	
	private Text txt_Sigkey;
	private Text txt_SigKeySize;
	
	private Text txt_Verifkey;
	private Text txt_VerKeySize;
	
	private Text txt_Hash;
	private Text txt_HashSize;
	
	private Text txt_Sig;
	private Text txt_SignatureSize;
	
	private Text txt_Bi;
	private Text txt_BSize;
	
	private Text txt_winternitzP;
	
	private Text txt_true_false;
	
	private Button btnWots;
	private Button btnWotsPlus;
	
	private Label lblMessageHash;
	private Label lblBi;
	private Label lblSignature;
	
	private Button btn_Genkey;
	private Button btn_VerifySig;
	private Button btn_Sign;
	
	private Label img_right;
	private Text txt_Output;
	
	// Parameter for WOTS/WOTS+
	private wots.OTS instance = new wots.WinternitzOTS(4);
	private String privateKey = "";
	private String publicKey = "";
	private String signature = "";
	private int w = 4;
	private int n = instance.getN();
	private int l = instance.getL();
	private String message = "";
	private String messageHash = files.Converter._byteToHex(instance.hashMessage(message));
	private String b = files.Converter._byteToHex(instance.initB());
	private boolean details = false;
	private boolean init = false;
	
	/**
	 * @wbp.nonvisual location=214,209
	 */
	//private final JFileChooser fileChooser = new JFileChooser();
	
	/**
	 * The content provider class is responsible for providing objects to the
	 * view. It can wrap existing objects in adapters or simply return objects
	 * as-is. These objects may be sensitive to the current input of the view,
	 * or ignore it and always show the same content (like Task List, for
	 * example).
	 */
	class ViewContentProvider implements IStructuredContentProvider {
		public void inputChanged(Viewer v, Object oldInput, Object newInput) {
		}

		public void dispose() {
		}

		public Object[] getElements(Object parent) {
			if (parent instanceof Object[]) {
				return (Object[]) parent;
			}
	        return new Object[0];
		}
	}

	class ViewLabelProvider extends LabelProvider implements
			ITableLabelProvider {
		public String getColumnText(Object obj, int index) {
			return getText(obj);
		}

		public Image getColumnImage(Object obj, int index) {
			return getImage(obj);
		}

		public Image getImage(Object obj) {
			return PlatformUI.getWorkbench().getSharedImages().getImage(
					ISharedImages.IMG_OBJ_ELEMENT);
		}
	}

	/**
	 * This is a callback that will allow us to create the viewer and initialize
	 * it.
	 */
	public void createPartControl(Composite parent) {
		parent.setToolTipText("");
		parent.setLayout(null);
		
		btn_Genkey = new Button(parent, SWT.NONE);
		btn_Genkey.addSelectionListener(new SelectionAdapter() {
			@Override
			public void widgetSelected(SelectionEvent e) {
				
				// KEY GENERATION
				
				if (btnWots.getSelection() && !btnWotsPlus.getSelection()) {
					
					// Set Image & Output field for WOTS
					txt_Output.setText("This message should explain the WOTS Key-Generation.");
					img_right.setImage(ResourceManager.getPluginImage("WOTS-Visualisierung_1", "images/Key_Generation.PNG"));
			    
				} else if (!btnWots.getSelection() && btnWotsPlus.getSelection()) {
					
					// Set Image & Output field for WOTS+
					txt_Output.setText("This message should explain the WOTS+ Key-Generation.");
					img_right.setImage(ResourceManager.getPluginImage("WOTS-Visualisierung_1", "images/WOTSPlus.PNG"));
					
				} else {
					
					// TODO ERROR MESSAGE
					
				}
				
				// Generate Keys
				setOutputs();
				instance.generateKeyPair();
				getOutputs();
			}
		});

		btn_Genkey.setBounds(10, 674, 116, 25);
		btn_Genkey.setText("Generate keys");
		
		btn_Sign = new Button(parent, SWT.NONE);
		btn_Sign.addSelectionListener(new SelectionAdapter() {
			@Override
			public void widgetSelected(SelectionEvent e) {
				
				// SIGNATURE GENERATION
				
				if (btnWots.getSelection() && !btnWotsPlus.getSelection()) {
				
					// Set Image & Output field for WOTS
					txt_Output.setText("This message should explain the WOTS Signature-Generation.");
					img_right.setImage(ResourceManager.getPluginImage("WOTS-Visualisierung_1", "images/Signature_Generation.PNG"));
					
				} else if (!btnWots.getSelection() && btnWotsPlus.getSelection()) {
					
					// Set Image & Output field for WOTS+
					txt_Output.setText("This message should explain the WOTS+ Key-Generation.");
					img_right.setImage(ResourceManager.getPluginImage("WOTS-Visualisierung_1", "images/WOTSPlus.PNG"));
					
				} else {
					
					// TODO ERROR MESSAGE
				}
				
				// Sign message and put Signature in Output Field
				setOutputs();
				instance.sign();
				getOutputs();
			}
		});
		btn_Sign.setText("Generate signature");
		btn_Sign.setBounds(132, 674, 146, 25);
		
		btn_VerifySig = new Button(parent, SWT.NONE);
		btn_VerifySig.addSelectionListener(new SelectionAdapter() {
			@Override
			public void widgetSelected(SelectionEvent e) {
				
				// SIGNATURE VERIFICATION
				
				if (btnWots.getSelection() && !btnWotsPlus.getSelection()) {
				
					// Set Image & Output field for WOTS
					txt_Output.setText("This message should explain the WOTS Signature-Verification.");
					img_right.setImage(ResourceManager.getPluginImage("WOTS-Visualisierung_1", "images/Signature_Verification.PNG"));
					
				} else if (!btnWots.getSelection() && btnWotsPlus.getSelection()) {
					
					// Set Image & Output field for WOTS+
					txt_Output.setText("This message should explain the WOTS+ Signature-Verification.");
					img_right.setImage(ResourceManager.getPluginImage("WOTS-Visualisierung_1", "images/WOTSPlus.PNG"));
					
				} else {
					
					// TODO ERROR MESSAGE
					
				}
				
				// Verify Signature
				if (instance.verify()) {
					txt_true_false.setText("Signature valid");
				} else {
					txt_true_false.setText("Signature rejected");
				}
			}
		});
		btn_VerifySig.setBounds(284, 674, 122, 25);
		btn_VerifySig.setText("Verify signature");
		
		Label lblWotsVisualization = new Label(parent, SWT.NONE);
		lblWotsVisualization.setBounds(10, 10, 140, 21);
		lblWotsVisualization.setText("WOTS Visualization");
		
		Label lblMessage = new Label(parent, SWT.NONE);
		lblMessage.setBounds(10, 37, 86, 21);
		lblMessage.setText("Message");
		
		txt_message = new Text(parent, SWT.BORDER | SWT.WRAP | SWT.V_SCROLL | SWT.MULTI);
		txt_message.setBounds(9, 58, 679, 96);
		txt_message.addModifyListener(new ModifyListener() {
			
			@Override
			public void modifyText(ModifyEvent e) {
				
				message = txt_message.getText();
				messageHash = files.Converter._byteToHex(instance.hashMessage(message));
				b = files.Converter._byteToHex(instance.initB());
				
				if (init) {
					txt_Hash.setText(messageHash);
					txt_Bi.setText(b);
					txt_MessageSize.setText(Integer.toString(files.Converter._stringToByte(message).length) + " Bytes");
				}
			}
		});
		
		Button btnLoadMessageFrom = new Button(parent, SWT.NONE);
		btnLoadMessageFrom.addSelectionListener(new SelectionAdapter() {
			public void widgetSelected(SelectionEvent e) {
				JFileChooser chooser = new JFileChooser();
			    //FileNameExtensionFilter filter = new FileNameExtensionFilter(
			    //    "JPG & GIF Images", "jpg", "gif");
			    //chooser.setFileFilter(filter);
			    int returnVal = chooser.showOpenDialog(null);
			    if(returnVal == JFileChooser.APPROVE_OPTION) {
			       System.out.println("You chose to open this file: " +
			            chooser.getSelectedFile().getName());
			       
			       File file = chooser.getSelectedFile();
			       String path = file.getAbsolutePath();
			       try {
						txt_message.setText(files.WotsComposite.readFile(path));
					} catch (IOException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					}
			    }
			}
		});
		btnLoadMessageFrom.setBounds(10, 160, 177, 25);
		btnLoadMessageFrom.setText("Load message from file");
		
		Label lblWinternitzParameterw = new Label(parent, SWT.NONE);
		lblWinternitzParameterw.setBounds(10, 200, 140, 21);
		lblWinternitzParameterw.setText("Winternitz Parameter (w)");
		
		txt_winternitzP = new Text(parent, SWT.BORDER);
		txt_winternitzP.setText("4");
		txt_winternitzP.setBounds(156, 197, 31, 21);
		txt_winternitzP.addModifyListener(new ModifyListener() {
			
			@Override
			public void modifyText(ModifyEvent e) {
				
				w = Integer.parseInt(txt_winternitzP.getText());
				instance.setW(w);
			}
		});
		
		Label lblHashFunction = new Label(parent, SWT.NONE);
		lblHashFunction.setBounds(10, 224, 96, 25);
		lblHashFunction.setText("Hash function");
		
		Combo cmb_Hash = new Combo(parent, SWT.NONE);
		cmb_Hash.setBounds(112, 221, 75, 23);
		cmb_Hash.setText("SHA-256");
		
		Label lblSignatureKey = new Label(parent, SWT.NONE);
		lblSignatureKey.setBounds(10, 262, 93, 20);
		lblSignatureKey.setText("Signature key");
		
		Label lblVerificationKey = new Label(parent, SWT.NONE);
		lblVerificationKey.setBounds(352, 262, 111, 20);
		lblVerificationKey.setText("Verification key");
		
		txt_Sigkey = new Text(parent, SWT.BORDER | SWT.WRAP | SWT.V_SCROLL | SWT.MULTI);
		txt_Sigkey.setText("");
		txt_Sigkey.setBounds(10, 283, 336, 151);
		txt_Sigkey.addModifyListener(new ModifyListener() {
			
			@Override
			public void modifyText(ModifyEvent e) {
				
				privateKey = txt_Sigkey.getText();
				txt_SigKeySize.setText(Integer.toString(files.Converter._stringToByte(privateKey).length/2) + "/" + (n*l) + "B");
			
				if (files.Converter._stringToByte(privateKey).length/2 != n*l) {
					btn_Genkey.setEnabled(false);
					btn_Sign.setEnabled(false);
					btn_VerifySig.setEnabled(false);
				} else {
					btn_Genkey.setEnabled(true);
					btn_Sign.setEnabled(true);
					btn_VerifySig.setEnabled(true);
				}
			}
		});
		
		txt_Verifkey = new Text(parent, SWT.BORDER | SWT.WRAP | SWT.V_SCROLL | SWT.MULTI);
		txt_Verifkey.setBounds(352, 283, 336, 151);
		txt_Verifkey.addModifyListener(new ModifyListener() {
			
			@Override
			public void modifyText(ModifyEvent e) {
				
				publicKey = txt_Verifkey.getText();
				txt_VerKeySize.setText(Integer.toString(files.Converter._stringToByte(publicKey).length/2) + "/" + (n*instance.getPublicKeyLength()) + "B");
			
				if (files.Converter._stringToByte(publicKey).length/2 != (n*instance.getPublicKeyLength())) {
					btn_Genkey.setEnabled(false);
					btn_Sign.setEnabled(false);
					btn_VerifySig.setEnabled(false);
				} else {
					btn_Genkey.setEnabled(true);
					btn_Sign.setEnabled(true);
					btn_VerifySig.setEnabled(true);
				}
			}
		});
		
		lblSignature = new Label(parent, SWT.NONE);
		lblSignature.setBounds(10, 463, 75, 21);
		lblSignature.setText("Signature");
		
		txt_Sig = new Text(parent, SWT.BORDER | SWT.WRAP | SWT.V_SCROLL | SWT.MULTI);
		txt_Sig.setBounds(10, 490, 570, 107);
		txt_Sig.addModifyListener(new ModifyListener() {
			
			@Override
			public void modifyText(ModifyEvent e) {
				
				signature = txt_Sig.getText();
				txt_SignatureSize.setText(Integer.toString(files.Converter._stringToByte(signature).length/2) + "/" + (n*l) + "B");
			
				if (files.Converter._stringToByte(signature).length/2 != n*l) {
					btn_Genkey.setEnabled(false);
					btn_Sign.setEnabled(false);
					btn_VerifySig.setEnabled(false);
				} else {
					btn_Genkey.setEnabled(true);
					btn_Sign.setEnabled(true);
					btn_VerifySig.setEnabled(true);
				}
			}
		});
		
		Button btn_reset = new Button(parent, SWT.NONE);
		btn_reset.addSelectionListener(new SelectionAdapter() {
			@Override
			public void widgetSelected(SelectionEvent e) {
				
				instance = new wots.WinternitzOTS(4);
				privateKey = "";
				publicKey = "";
				signature = "";
				w = 4;
				message = "standard message";
				messageHash = files.Converter._byteToHex(instance.hashMessage(message));
				b = files.Converter._byteToHex(instance.initB());
				
				txt_message.setText("standard message");
				txt_Sigkey.setText("");
				txt_Sig.setText("");
				txt_Verifkey.setText("");
				txt_winternitzP.setText("4");
				txt_true_false.setText("");
				txt_Output.setText("This is the welcome message of our plugin, please insert something which makes more sense!");
				img_right.setImage(ResourceManager.getPluginImage("WOTS-Visualisierung_1", "images/Overview2.PNG"));
				txt_Hash.setText(messageHash);
				txt_Bi.setText(b);
				
				btnWots.setSelection(true);
				btnWotsPlus.setSelection(false);
			}
		});
		btn_reset.setBounds(520, 674, 75, 25);
		btn_reset.setText("Reset");
		
		txt_true_false = new Text(parent, SWT.BORDER | SWT.WRAP | SWT.CENTER);
		txt_true_false.setEditable(false);
		txt_true_false.setBounds(586, 490, 102, 107);
		txt_message.setText("standard message");
		img_right = new Label(parent, 0);
		img_right.setBounds(723, 346, 483, 322);
		img_right.setImage(ResourceManager.getPluginImage("WOTS-Visualisierung_1", "images/Overview2.PNG"));
		
		btnWots = new Button(parent, SWT.RADIO);
		btnWots.setBounds(352, 186, 111, 20);
		btnWots.setText("WOTS");
		btnWots.setSelection(true);
		btnWots.addSelectionListener( new SelectionListener() {
			
			@Override
			public void widgetSelected(SelectionEvent e) {

				instance = new wots.WinternitzOTS(w);
				privateKey = "";
				publicKey = "";
				signature = "";
				txt_Sigkey.setText("");
				txt_Verifkey.setText("");
				txt_Sig.setText("");
			}
			
			@Override
			public void widgetDefaultSelected(SelectionEvent e) {	
			}
		});
		
		btnWotsPlus = new Button(parent, SWT.RADIO);
		btnWotsPlus.setBounds(352, 217, 111, 20);
		btnWotsPlus.setText("WOTS+");
		btnWotsPlus.addSelectionListener( new SelectionListener() {
			
			@Override
			public void widgetSelected(SelectionEvent e) {

				instance = new wots.WOTSPlus(w);
				privateKey = "";
				publicKey = "";
				signature = "";
				txt_Sigkey.setText("");
				txt_Verifkey.setText("");
				txt_Sig.setText("");
			}
			
			@Override
			public void widgetDefaultSelected(SelectionEvent e) {	
			}
		});
		
		txt_Output = new Text(parent, SWT.BORDER | SWT.WRAP | SWT.MULTI);
		txt_Output.setEditable(false);
		txt_Output.setBounds(723, 58, 483, 282);
		txt_Output.setText("This is the welcome message of our plugin, please insert something which makes more sense!");
		
		Button btn_Details = new Button(parent, SWT.NONE);
		btn_Details.addSelectionListener(new SelectionAdapter() {
			@Override
			public void widgetSelected(SelectionEvent e) {
				
				if (!details) {
					
					// Sets the View to a more detailed Version
					
					details = true;
					
					txt_Hash.setEnabled(true);
					txt_Hash.setVisible(true);
					
					lblMessageHash.setEnabled(true);
					lblMessageHash.setVisible(true);
					
					txt_Bi.setEnabled(true);
					txt_Bi.setVisible(true);
					
					lblBi.setEnabled(true);
					lblBi.setVisible(true);
					
					txt_HashSize.setEnabled(true);
					txt_HashSize.setVisible(true);
					
					txt_BSize.setEnabled(true);
					txt_BSize.setVisible(true);
					
					// Compress txt_fields to fit detailed view
					
					txt_message.setBounds(9, 58, 337, 96);
					txt_MessageSize.setBounds(268, 159, 78, 26);
					
					txt_Sigkey.setBounds(10, 283, 336, 75);
					txt_SigKeySize.setBounds(238, 363, 108, 26);
					
					txt_Verifkey.setBounds(352, 283, 336, 75);
					txt_VerKeySize.setBounds(580, 363, 108, 26);
					
					txt_Sig.setBounds(10, 531, 570, 107);
					txt_SignatureSize.setBounds(472, 642, 108, 26);
					txt_true_false.setBounds(586, 531, 102, 107);
					lblSignature.setBounds(10, 500, 75, 21);
					
				} else if (details) {
					
					// Hides the details shown before
					
					details = false;
					
					txt_Hash.setEnabled(false);
					txt_Hash.setVisible(false);
					
					lblMessageHash.setEnabled(false);
					lblMessageHash.setVisible(false);
					
					txt_Bi.setEnabled(false);
					txt_Bi.setVisible(false);
					
					lblBi.setEnabled(false);
					lblBi.setVisible(false);
					
					txt_HashSize.setEnabled(false);
					txt_HashSize.setVisible(false);
					
					txt_BSize.setEnabled(false);
					txt_BSize.setVisible(false);
					
					// Set sizes back to original
					
					txt_message.setBounds(9, 58, 679, 96);
					txt_MessageSize.setBounds(610, 159, 78, 26);
			
					txt_Sigkey.setBounds(10, 283, 336, 151);
					txt_SigKeySize.setBounds(238, 440, 108, 26);
					
					txt_Verifkey.setBounds(352, 283, 336, 151);
					txt_VerKeySize.setBounds(580, 440, 108, 26);
					
					txt_Sig.setBounds(10, 490, 570, 107);
					txt_SignatureSize.setBounds(472, 603, 108, 26);
					txt_true_false.setBounds(586, 490, 102, 107);
					lblSignature.setBounds(10, 463, 75, 21);
				
				} else {
					// TODO error message
				}		
			}
		});
		btn_Details.setBounds(412, 674, 102, 25);
		btn_Details.setText("Toggle Details");
		
		txt_Hash = new Text(parent, SWT.BORDER | SWT.WRAP | SWT.V_SCROLL | SWT.MULTI);
		txt_Hash.setBounds(352, 58, 336, 96);
		txt_Hash.setEnabled(false);
		txt_Hash.setVisible(false);
		txt_Hash.setText(messageHash);
		txt_Hash.addModifyListener(new ModifyListener() {
			
			@Override
			public void modifyText(ModifyEvent e) {
				
				messageHash = txt_Hash.getText();
				instance.setMessage(files.Converter._hexStringToByte(messageHash));
				b = files.Converter._byteToHex(instance.initB());
				
				if (init) {
					txt_Bi.setText(b);
					txt_HashSize.setText(Integer.toString(files.Converter._stringToByte(messageHash).length/2) + "/" + n + "B");
				}
				
				if (files.Converter._stringToByte(messageHash).length/2 != n) {
					btn_Genkey.setEnabled(false);
					btn_Sign.setEnabled(false);
					btn_VerifySig.setEnabled(false);
				} else {
					btn_Genkey.setEnabled(true);
					btn_Sign.setEnabled(true);
					btn_VerifySig.setEnabled(true);
				}
			}
		});
		
		lblMessageHash = new Label(parent, SWT.NONE);
		lblMessageHash.setBounds(354, 37, 109, 20);
		lblMessageHash.setText("Message Hash");
		lblMessageHash.setEnabled(false);
		lblMessageHash.setVisible(false);
		
		txt_Bi = new Text(parent, SWT.BORDER | SWT.WRAP | SWT.V_SCROLL | SWT.MULTI);
		txt_Bi.setBounds(10, 415, 678, 56);
		txt_Bi.setEnabled(false);
		txt_Bi.setVisible(false);
		txt_Bi.setText(b);
		txt_Bi.addModifyListener(new ModifyListener() {
			
			@Override
			public void modifyText(ModifyEvent e) {
				
				b = txt_Bi.getText();
				instance.setBi(files.Converter._hexStringToByte(b));
				txt_BSize.setText(Integer.toString(files.Converter._stringToByte(b).length/2) + "/" + l + "B");
			
				if (files.Converter._stringToByte(b).length/2 != l) {
					btn_Genkey.setEnabled(false);
					btn_Sign.setEnabled(false);
					btn_VerifySig.setEnabled(false);
				} else {
					btn_Genkey.setEnabled(true);
					btn_Sign.setEnabled(true);
					btn_VerifySig.setEnabled(true);
				}
			}
		});
		
		lblBi = new Label(parent, SWT.NONE);
		lblBi.setBounds(10, 389, 70, 20);
		lblBi.setText("Bi");
		lblBi.setEnabled(false);
		lblBi.setVisible(false);
		
		txt_MessageSize = new Text(parent, SWT.BORDER | SWT.READ_ONLY);
		txt_MessageSize.setBounds(610, 159, 78, 26);
		txt_MessageSize.setText(Integer.toString(files.Converter._stringToByte(message).length) + " Bytes");
		
		txt_SigKeySize = new Text(parent, SWT.BORDER | SWT.READ_ONLY);
		txt_SigKeySize.setBounds(238, 440, 108, 26);
		txt_SigKeySize.setText(Integer.toString(files.Converter._stringToByte(privateKey).length/2) + "/" + (n*l) + "B");
		
		txt_VerKeySize = new Text(parent, SWT.BORDER | SWT.READ_ONLY);
		txt_VerKeySize.setBounds(580, 440, 108, 26);
		txt_VerKeySize.setText(Integer.toString(files.Converter._stringToByte(publicKey).length/2) + "/" + (n*instance.getPublicKeyLength()) + "B");
		
		txt_HashSize = new Text(parent, SWT.BORDER | SWT.READ_ONLY);
		txt_HashSize.setBounds(610, 159, 78, 26);
		txt_HashSize.setText(Integer.toString(files.Converter._hexStringToByte(messageHash).length) + "/" + n + "B");
		txt_HashSize.setEnabled(false);
		txt_HashSize.setVisible(false);
		
		txt_SignatureSize = new Text(parent, SWT.BORDER | SWT.READ_ONLY);
		txt_SignatureSize.setBounds(472, 603, 108, 26);
		txt_SignatureSize.setText(Integer.toString(files.Converter._stringToByte(signature).length/2) + "/" + (n*l) + "B");
		
		txt_BSize = new Text(parent, SWT.BORDER | SWT.READ_ONLY);
		txt_BSize.setBounds(610, 477, 78, 26);
		txt_BSize.setText(Integer.toString(files.Converter._hexStringToByte(b).length) + "/" + l + "B");
		txt_BSize.setEnabled(false);
		txt_BSize.setVisible(false);
		
		init = true;
		message = "standard message";
	}

	/**
	 * Passing the focus request to the viewer's control.
	 */
	public void setFocus() {
		//viewer.getControl().setFocus();
	}
	
	public void setOutputs() {
		
		instance.setW(w);
		instance.setPrivateKey(files.Converter._hexStringTo2dByte(privateKey, instance.getLength()));
		instance.setPublicKey(files.Converter._hexStringTo2dByte(publicKey, instance.getPublicKeyLength()));
		instance.setSignature(files.Converter._hexStringToByte(signature));
		instance.setMessage(files.Converter._hexStringToByte(messageHash));
		instance.setBi(files.Converter._hexStringToByte(b));
	}
	
	public void getOutputs() {
		this.privateKey = files.Converter._2dByteToHex(instance.getPrivateKey());
		this.publicKey = files.Converter._2dByteToHex(instance.getPublicKey());
		this.signature = files.Converter._byteToHex(instance.getSignature());
		this.messageHash = files.Converter._byteToHex(instance.getMessageHash());
		this.b = files.Converter._byteToHex(instance.getBi());
		this.n = instance.getN();
		this.l = instance.getL();
		
		txt_Sigkey.setText(privateKey);
		txt_Verifkey.setText(publicKey);
		txt_Bi.setText(b);
		txt_Sig.setText(signature);
		txt_Hash.setText(messageHash);
	}
}

