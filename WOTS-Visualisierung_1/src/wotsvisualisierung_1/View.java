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
import org.eclipse.wb.swt.SWTResourceManager;

public class View extends ViewPart {
	public View() {
		setPartName("WOTS-Visualisierung");
	}
	public static final String ID = "asdf.view";
	public Text txt_message;
	private Text txt_winternitzP;
	private Text txt_Sigkey;
	private Text text_1;
	private Text txt_Verifkey;
	private Text txt_Sig;
	private Text text;
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
				
				byte[] seed;
				int w = Integer.parseInt(txt_winternitzP.getText());
				
				wots.WinternitzOTS instance = new wots.WinternitzOTS(w);
				files.PseudorandomFunction prf = new files.AESPRF.AES128();
				int n = prf.getLength();
			    SecureRandom sRandom = new SecureRandom();
			    seed = new byte[n];
			    
			    sRandom.nextBytes(seed);

			    byte[] x = new byte[n];
				
			    sRandom.nextBytes(x);
			    instance.init(prf, x);
			    
			    instance.generatePrivateKey(seed);
			    instance.generatePublicKey();
			    
			    // TODO parse byte[][] keys to Hex values
			    // txt_Sigkey.setText(files.Converter._2dByteToHex(instance.getPrivateKey()));
			    txt_Verifkey.setText(files.Converter._2dByteToHex(instance.getPublicKey()));
			}
		});

		btn_Genkey.setBounds(10, 615, 93, 25);
		btn_Genkey.setText("Generate keys");
		
		Button btnNewButton_1 = new Button(parent, SWT.NONE);
		btnNewButton_1.addSelectionListener(new SelectionAdapter() {
			@Override
			public void widgetSelected(SelectionEvent e) {
				
				int w = Integer.parseInt(txt_winternitzP.getText());
				
				wots.WinternitzOTS instance = new wots.WinternitzOTS(w);
				
				// TODO parse txt_SigKey to byte[][] privateKey
				
				byte[][] privateKey = null;
				instance.setPrivateKey(privateKey);
				
				// TODO parse txt_message to byte[] message and return value to Hex
				
				byte[] message = null;
				txt_Sig.setText(instance.sign(message).toString());
				
			}
		});
		btnNewButton_1.setText("Generate signature");
		btnNewButton_1.setBounds(106, 615, 111, 25);
		
		Button btn_VerifySig = new Button(parent, SWT.NONE);
		btn_VerifySig.addSelectionListener(new SelectionAdapter() {
			@Override
			public void widgetSelected(SelectionEvent e) {
				
				int w = Integer.parseInt(txt_winternitzP.getText());
				
				wots.WinternitzOTS instance = new wots.WinternitzOTS(w);
				
				// TODO parse txt_Verifkey to byte[][] privateKey
				
				byte[][] publicKey = null;
				instance.setPublicKey(publicKey);
				
				// TODO Parse message & signature to byte[]
				
				byte[] message = null;
				byte[] signature = null;
				
				if (instance.verify(message, signature) == true) {
					// TODO message Box
				} else {
					// TODO message Box
				}
				
				
			}
		});
		btn_VerifySig.setBounds(223, 615, 100, 25);
		btn_VerifySig.setText("Verify signature");
		
		Label lblWotsVisualization = new Label(parent, SWT.NONE);
		lblWotsVisualization.setBounds(10, 10, 126, 15);
		lblWotsVisualization.setText("WOTS Visualization");
		
		Label lblMessage = new Label(parent, SWT.NONE);
		lblMessage.setBounds(10, 37, 55, 15);
		lblMessage.setText("Message");
		
		txt_message = new Text(parent, SWT.BORDER | SWT.MULTI);
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
		btnLoadMessageFrom.setBounds(10, 160, 154, 25);
		btnLoadMessageFrom.setText("Load message from file");
		
		Label lblWinternitzParameterw = new Label(parent, SWT.NONE);
		lblWinternitzParameterw.setBounds(10, 200, 140, 15);
		lblWinternitzParameterw.setText("Winternitz Parameter (w)");
		
		txt_winternitzP = new Text(parent, SWT.BORDER);
		txt_winternitzP.setText("4");
		txt_winternitzP.setBounds(156, 197, 31, 21);
		
		Label lblHashFunction = new Label(parent, SWT.NONE);
		lblHashFunction.setBounds(10, 224, 75, 15);
		lblHashFunction.setText("Hash function");
		
		Combo cmb_Hash = new Combo(parent, SWT.NONE);
		cmb_Hash.setBounds(112, 221, 75, 23);
		cmb_Hash.setText("SHA-1\r");
		
		Label lblSignatureKey = new Label(parent, SWT.NONE);
		lblSignatureKey.setBounds(10, 262, 93, 15);
		lblSignatureKey.setText("Signature key");
		
		Label lblVerificationKey = new Label(parent, SWT.NONE);
		lblVerificationKey.setBounds(352, 262, 111, 15);
		lblVerificationKey.setText("Verification key");
		
		txt_Sigkey = new Text(parent, SWT.BORDER);
		txt_Sigkey.setForeground(SWTResourceManager.getColor(SWT.COLOR_BLACK));
		txt_Sigkey.setBackground(SWTResourceManager.getColor(SWT.COLOR_WHITE));
		txt_Sigkey.setText("");
		txt_Sigkey.setBounds(10, 283, 336, 151);
		
		txt_Verifkey = new Text(parent, SWT.BORDER);
		txt_Verifkey.setBounds(352, 283, 336, 151);
		
		Label lblSignature = new Label(parent, SWT.NONE);
		lblSignature.setBounds(10, 477, 55, 15);
		lblSignature.setText("Signature");
		
		txt_Sig = new Text(parent, SWT.BORDER);
		txt_Sig.setBounds(10, 498, 678, 107);
		
		Button btn_reset = new Button(parent, SWT.NONE);
		btn_reset.addSelectionListener(new SelectionAdapter() {
			@Override
			public void widgetSelected(SelectionEvent e) {
				
				txt_message.setText("standard message");
				txt_Sigkey.setText("");
				txt_Sig.setText("");
				txt_Verifkey.setText("");
				txt_winternitzP.setText("4");
			}
		});
		btn_reset.setBounds(329, 615, 75, 25);
		btn_reset.setText("Reset");
		
		text = new Text(parent, SWT.BORDER);
		text.setBounds(282, 200, 75, 25);
		

	}

	/**
	 * Passing the focus request to the viewer's control.
	 */
	public void setFocus() {
		//viewer.getControl().setFocus();
	}
}

