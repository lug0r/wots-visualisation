package wotsvisualisierung_1;

import java.io.File;
import java.io.IOException;
import java.security.SecureRandom;

import javax.swing.JFileChooser;

import org.eclipse.jface.viewers.IStructuredContentProvider;
import org.eclipse.jface.viewers.ITableLabelProvider;
import org.eclipse.jface.viewers.LabelProvider;
import org.eclipse.jface.viewers.Viewer;
import org.eclipse.swt.SWT;
import org.eclipse.swt.events.SelectionAdapter;
import org.eclipse.swt.events.SelectionEvent;
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
	private Text txt_winternitzP;
	private Text txt_Sigkey;
	private Text txt_Verifkey;
	private Text txt_Sig;
	private Text txt_true_false;
	private Label img_right;
	private Button btnWots;
	private Button btnWotsPlus;
	private Text txt_Output;
	private Text txt_Hash;
	private Text txt_Bi;
	private boolean details = false;
	private Label lblMessageHash;
	private Label lblBi;
	
	private wots.WinternitzOTS instance = new wots.WinternitzOTS(4);
	private String privateKey = "";
	private String publicKey = "";
	private String signature = "";
	private int w = 4;
	private int n;
	private int l;
	private String message = "standard message";
	private String messageHash = files.Converter._byteToHex(instance.hashMessage(message));
	private String b = files.Converter._byteToHex(instance.initB());
	
	
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
		
		Button btn_Genkey = new Button(parent, SWT.NONE);
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

		btn_Genkey.setBounds(10, 615, 116, 25);
		btn_Genkey.setText("Generate keys");
		
		Button btnNewButton_1 = new Button(parent, SWT.NONE);
		btnNewButton_1.addSelectionListener(new SelectionAdapter() {
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
		btnNewButton_1.setText("Generate signature");
		btnNewButton_1.setBounds(132, 615, 146, 25);
		
		Button btn_VerifySig = new Button(parent, SWT.NONE);
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
		btn_VerifySig.setBounds(284, 615, 122, 25);
		btn_VerifySig.setText("Verify signature");
		
		Label lblWotsVisualization = new Label(parent, SWT.NONE);
		lblWotsVisualization.setBounds(10, 10, 140, 21);
		lblWotsVisualization.setText("WOTS Visualization");
		
		Label lblMessage = new Label(parent, SWT.NONE);
		lblMessage.setBounds(10, 37, 86, 21);
		lblMessage.setText("Message");
		
		txt_message = new Text(parent, SWT.BORDER | SWT.WRAP | SWT.V_SCROLL | SWT.MULTI);
		txt_message.setBounds(9, 58, 679, 96);
		
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
		
		txt_Verifkey = new Text(parent, SWT.BORDER | SWT.WRAP | SWT.V_SCROLL | SWT.MULTI);
		txt_Verifkey.setBounds(352, 283, 336, 151);
		
		Label lblSignature = new Label(parent, SWT.NONE);
		lblSignature.setBounds(10, 477, 75, 21);
		lblSignature.setText("Signature");
		
		txt_Sig = new Text(parent, SWT.BORDER | SWT.WRAP | SWT.V_SCROLL | SWT.MULTI);
		txt_Sig.setBounds(10, 498, 570, 107);
		
		Button btn_reset = new Button(parent, SWT.NONE);
		btn_reset.addSelectionListener(new SelectionAdapter() {
			@Override
			public void widgetSelected(SelectionEvent e) {
				
				txt_message.setText("standard message");
				txt_Sigkey.setText("");
				txt_Sig.setText("");
				txt_Verifkey.setText("");
				txt_winternitzP.setText("4");
				txt_true_false.setText("");
				txt_Output.setText("This is the welcome message of our plugin, please insert something which makes more sense!");
				img_right.setImage(ResourceManager.getPluginImage("WOTS-Visualisierung_1", "images/Overview2.PNG"));
//				Image img = new Image(org.eclipse.swt.widgets.Display.getCurrent(), "C:/Users/Hannes/Desktop/Studium/4.Semester/Projekt/Images/Konzept/Overview2.PNG");
//				img_right.setImage(img);
				txt_Hash.setText("");
				txt_Bi.setText("");
			}
		});
		btn_reset.setBounds(520, 615, 75, 25);
		btn_reset.setText("Reset");
		
		txt_true_false = new Text(parent, SWT.BORDER | SWT.WRAP | SWT.CENTER);
		txt_true_false.setEditable(false);
		txt_true_false.setBounds(586, 498, 102, 107);
		txt_message.setText("standard message");
		img_right = new Label(parent, 0);
		img_right.setBounds(723, 283, 483, 322);
		img_right.setImage(ResourceManager.getPluginImage("WOTS-Visualisierung_1", "images/Overview2.PNG"));

//		Image img = new Image(org.eclipse.swt.widgets.Display.getCurrent(), "C:/Users/Hannes/Desktop/Studium/4.Semester/Projekt/Images/Konzept/Overview2.PNG");
//		img_right.setImage(img);
		
		btnWots = new Button(parent, SWT.RADIO);
		btnWots.setBounds(352, 186, 111, 20);
		btnWots.setText("WOTS");
		btnWots.setSelection(true);
		
		btnWotsPlus = new Button(parent, SWT.RADIO);
		btnWotsPlus.setBounds(352, 217, 111, 20);
		btnWotsPlus.setText("WOTS+");
		
		txt_Output = new Text(parent, SWT.BORDER | SWT.WRAP | SWT.MULTI);
		txt_Output.setEditable(false);
		txt_Output.setBounds(723, 58, 483, 191);
		txt_Output.setText("This is the welcome message of our plugin, please insert something which makes more sense!");
		
		Button btn_Details = new Button(parent, SWT.NONE);
		btn_Details.addSelectionListener(new SelectionAdapter() {
			@Override
			public void widgetSelected(SelectionEvent e) {
				
				if (!details) {
					
					// Explains what is different to normal Version
					
					txt_Output.setText("This is a more detailed view of the WOTS/WOTS+ algorithm. In this view you are able to take a look and edit the hash of the message and the calculated Bitstring Bi.\nTo use the detailed version properly, you have to generate the Hash and the Bitstring Bi manually by clicking on the Buttons \"Hash Message\" and \"Calculate Bi\".");
					
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
					
					// Compress txt_fields to fit detailed view
					
					txt_message.setBounds(9, 58, 337, 96);
					txt_Sigkey.setBounds(10, 283, 336, 75);
					txt_Verifkey.setBounds(352, 283, 336, 75);
					
				} else if (details) {
					
					// States that now the normal view is showed
					
					txt_Output.setText("You switched back to the normal view of the WOTS/WOTS+ algorithm.");
					
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
					
					// Set sizes back to original
					
					txt_message.setBounds(9, 58, 679, 96);
					txt_Sigkey.setBounds(10, 283, 336, 151);
					txt_Verifkey.setBounds(352, 283, 336, 151);
					
				
				} else {
					// TODO error message
				}		
			}
		});
		btn_Details.setBounds(412, 615, 102, 25);
		btn_Details.setText("Toggle Details");
		
		txt_Hash = new Text(parent, SWT.BORDER | SWT.WRAP | SWT.V_SCROLL | SWT.MULTI);
		txt_Hash.setBounds(352, 58, 336, 96);
		txt_Hash.setEnabled(false);
		txt_Hash.setVisible(false);
		
		lblMessageHash = new Label(parent, SWT.NONE);
		lblMessageHash.setBounds(354, 37, 109, 20);
		lblMessageHash.setText("Message Hash");
		lblMessageHash.setEnabled(false);
		lblMessageHash.setVisible(false);
		
		txt_Bi = new Text(parent, SWT.BORDER | SWT.WRAP | SWT.V_SCROLL | SWT.MULTI);
		txt_Bi.setBounds(10, 415, 678, 56);
		txt_Bi.setEnabled(false);
		txt_Bi.setVisible(false);
		
		lblBi = new Label(parent, SWT.NONE);
		lblBi.setBounds(10, 389, 70, 20);
		lblBi.setText("Bi");
		lblBi.setEnabled(false);
		lblBi.setVisible(false);
		

		
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
		instance.setPublicKey(files.Converter._hexStringTo2dByte(publicKey, instance.getLength()));
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
		
		txt_Sigkey.setText(privateKey);
		txt_Verifkey.setText(publicKey);
		txt_Bi.setText(b);
		txt_Sig.setText(signature);
		txt_Hash.setText(messageHash);
	}
}

