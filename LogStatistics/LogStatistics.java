package piat.p2.regExp;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

public class LogStatistics {
	
	HashMap<String, HashMap<String, Integer>> tableMSA = new HashMap<String, HashMap<String, Integer>>();
	HashMap<String, HashMap<String, Integer>> tableSCI = new HashMap<String, HashMap<String, Integer>>();
	HashMap<String, HashMap<String, Integer>> tableSCO = new HashMap<String, HashMap<String, Integer>>();
	HashMap<String, HashMap<String, Integer>> tableSMI = new HashMap<String, HashMap<String, Integer>>();
	HashMap<String, HashMap<String, Integer>> tableSMO = new HashMap<String, HashMap<String, Integer>>();
	HashMap<String, HashMap<String, Integer>> tableUMB = new HashMap<String, HashMap<String, Integer>>();
	
	private ArrayList<File> comprobar(String pathInput) {
		final File folder = new File(pathInput);
		if(!folder.exists()) {
			System.err.println("El directorio especificado no existe");
			return null;
		}
		if(!folder.isDirectory()) {
			System.err.println("El pathInput especificado no es un directorio");
			return null;
		}
		if(!folder.canRead()) {
			System.err.println("El directorio especificado no tiene permisos de lectura");
			return null;
		}
		ArrayList<File> files = logs(folder);
		return files;
	}
	
	private ArrayList<File> logs(File folder){
		File [] files = folder.listFiles(new FilenameFilter() {
			public boolean accept(File folder, String name) {
				return name.endsWith(".log");
			}
		});

		ArrayList<File> log = new ArrayList<File>();
		for(File logs : files) {
			log.add(logs);
		}
		return log;

	}
	
	public void procesar(String path) {
		try {
			ArrayList<File> files = comprobar(path);
			if(files == null) {
				return;
			}
			BufferedReader reader = null;
			PrintWriter writer = new PrintWriter(new File(path + "\\estadisticos.txt"));
			
			HashMap<String, Integer> serverTypes = new HashMap<String, Integer>();
			HashMap<String, Integer> cuentasEmisoras = new HashMap<String, Integer>();
			ArrayList<String> numbers = new ArrayList<String>();
			int lines = 1;
			int formatErrors = 0;
			Pattern pt = Pattern.compile("^([0-9]{4}[-][0-9]{2}[-][0-9]{2}) ((0[0-9]|1[0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]) ([a-z-]+[\\d]) (\\[[A-Z0-9]{8}\\]:) (.*?)$");
			Pattern c = Pattern.compile("([4-5][.][0-9][.][0-9])\\s");
			Pattern block = Pattern.compile("SEC-BLOCKED");
			Pattern inf = Pattern.compile(".security-[^:]+:\\sINFECTED.");
			Pattern spam = Pattern.compile(".security-[^:]+:\\sSPAM$");
			Pattern ioput = Pattern.compile("\\smessage-id");
			Pattern storage = Pattern.compile("stored");
			Pattern cuenta = Pattern.compile("^message from: [<]([\\w-]+.[\\w-]+)@[A-Za-z0-9]+.[A-Za-z0-9]+.[A-Za-z]{2,}[>]");
			for(File f : files) {
				reader = new BufferedReader(new FileReader(f));
				String line;
				String date = new String();
				String server = new String();
				String trace = new String();
				while((line = reader.readLine()) != null) {
					Matcher mt = pt.matcher(line);
					if(mt.matches()) {
						date = mt.group(1);
						server = mt.group(4);
						trace = mt.group(6);
					}
					else {
						formatErrors++;
						continue;
					}
					String[] type;
					type = server.split("(?<=\\D)(?=\\d)|(?<=\\d)(?=\\D)");
					lines++;
					String code = new String();
					
					Matcher cc = c.matcher(trace);
					Matcher blocked = block.matcher(trace);
					Matcher infM = inf.matcher(trace);
					Matcher spamM = spam.matcher(trace);
					Matcher st = storage.matcher(trace);
					Matcher io = ioput.matcher(trace);
					Matcher cEmisora = cuenta.matcher(trace);

					if(type[0].equals("smtp-in") && io.find()) {
						chooseTable(type[0], date, "msgInput");
					}
					if(type[0].equals("smtp-out") && io.find()) {
						chooseTable(type[0], date, "msgOutput");
					}
					if(type[0].equals("user-mailbox") && st.find()) {
						chooseTable(type[0], date, "msgStored");
					}
					if(cc.find()) {
						code = cc.group(); 	// code = 4.3.2 or 5.1.1
						code = code.substring(0, code.length() - 1);
						String cd = "code ";
						cd += code;
						chooseTable(type[0], date, cd);
					}
					if(blocked.find()) {
						chooseTable(type[0], date, "msgBLOCKED");
					}
					if(infM.find()) {
						chooseTable(type[0], date, "msgINFECTED");
					}
					if(spamM.find()) {
						chooseTable(type[0], date, "msgSPAM");
					}
					if(type[0].equals("msa") && cEmisora.find()) {
						String key = cEmisora.group(1);
						if(cuentasEmisoras.containsKey(key)) {
							cuentasEmisoras.put(key, cuentasEmisoras.get(key) + 1);
						}
						else {
							cuentasEmisoras.put(key, 1);
						}
					}
					addServerType(serverTypes, server, numbers);
				}
			}
			Iterator<Map.Entry<String, Integer>> entries = cuentasEmisoras.entrySet().iterator();
			while(entries.hasNext()) {
				if(entries.next().getValue() < 500) {
					entries.remove();
				}
			}
			
			// Ordenar cuentas emisoras por orden alfabetico
			TreeMap<String, Integer> cuentasOrdenadas = new TreeMap<String, Integer>();
			cuentasOrdenadas.putAll(cuentasEmisoras);
			cuentasEmisoras.clear();
			String sTypes = serverTypes.toString();
			sTypes = sTypes.substring(1, sTypes.length() - 1);
			System.out.println("Estadisticos Generales: \n");
			System.out.println("Servers: " + sTypes);
			System.out.println("Files number: " + files.size());
			System.out.println("Lines number: " + lines);
			System.out.println("Format error numbers: " + formatErrors + "\n");
			System.out.println("Estadisticos agregados por tipo de servidor y dia: \n");
			System.out.println("msa: " + tableMSA.toString());
			System.out.println("security-in: " + tableSCI.toString());
			System.out.println("security-out: " + tableSCO.toString());
			System.out.println("smtp-in: " + tableSMI.toString());
			System.out.println("smtp-out: " + tableSMO.toString());
			System.out.println("user-mailbox: " + tableUMB.toString() + "\n");
			System.out.println("Estadisticos agregados por cuenta emisora: \n");
			System.out.println(cuentasOrdenadas.toString());
			
			//////////////////////////////////////////////////////////////////////
			writer.println("Estadisticos Generales: \n");
			writer.println("Servers: " + sTypes);
			writer.println("Files number: " + files.size());
			writer.println("Lines number: " + lines);
			writer.println("Format error numbers: " + formatErrors + "\n");
			writer.println("--------------------------------------------------\n");
			writer.println("Estadisticos agregados por tipo de servidor y dia: \n");
			writer.println("- msa:");
			tablePrinter(writer, tableMSA);
			writer.println("+++++++++++++++++++++");
			writer.println("- security-in:");
			tablePrinter(writer, tableSCI);
			writer.println("+++++++++++++++++++++");
			writer.println("- security-out:");
			tablePrinter(writer, tableSCO);
			writer.println("+++++++++++++++++++++");
			writer.println("- smtp-in:");
			tablePrinter(writer, tableSMI);
			writer.println("+++++++++++++++++++++");
			writer.println("- smtp-out:");
			tablePrinter(writer, tableSMO);
			writer.println("+++++++++++++++++++++");
			writer.println("- user-mailbox:");
			tablePrinter(writer, tableUMB);
			writer.println("\n--------------------------------------------------\n");
			writer.println("Estadisticos agregados por cuenta emisora: \n");
			for(Map.Entry<String, Integer> acc : cuentasOrdenadas.entrySet()) {
				writer.print(acc.getKey() + " ==> " + acc.getValue() + "\n");
			}
			//////////////////////////////////////////////////////////////////////
			reader.close();
			writer.close();
		} catch (IOException e) {
			e.printStackTrace();
			System.err.println("Error de E/S");
		}
	}
	
	private void tablePrinter(PrintWriter writer, HashMap<String, HashMap<String, Integer>> table) {
		int i = 0;
		for(Map.Entry<String, HashMap<String, Integer>> msa : table.entrySet()) {
			if(i > 0) {
				writer.println("\n" + msa.getKey());
			}
			else {
				writer.println(msa.getKey());
			}
			for(Map.Entry<String, Integer> day : msa.getValue().entrySet()) {
				writer.print("\t" + day.getKey() + " ==> ");
				writer.print(day.getValue() + "\n");
			}
			i++;
		}
	}
	
	private void chooseTable(String type, String date, String key) {
		switch(type) {
		case "msa":
			addServerData(tableMSA, date, key);
			break;
		case "security-in":
			addServerData(tableSCI, date, key);
			break;
		case "security-out":
			addServerData(tableSCO, date, key);
			break;
		case "smtp-in":
			addServerData(tableSMI, date, key);
			break;
		case "smtp-out":
			addServerData(tableSMO, date, key);
			break;
		case "user-mailbox":
			addServerData(tableUMB, date, key);
			break;
		}
	}
	
	private void addServerData(HashMap<String, HashMap<String, Integer>> table, String date, String key) {
		if(table.containsKey(date)) {
			if(table.get(date).containsKey(key)) {
				table.get(date).put(key, table.get(date).get(key) + 1);
			}
			else {
				table.get(date).put(key, 1);
			}
		}
		else {
			table.put(date, new HashMap<String, Integer>());
			table.get(date).put(key, 1);
		}
	}
	
	private void addServerType(HashMap<String, Integer> serverTypes, String data2, ArrayList<String> numbers) {
		String[] server;
		server = data2.split("(?<=\\D)(?=\\d)|(?<=\\d)(?=\\D)");
		if(!serverTypes.containsKey(server[0])) {
			serverTypes.put(server[0], 1);
			numbers.add(data2);
		}
		else if(serverTypes.containsKey(server[0])) {
			int i = 0;
			boolean found = false;
			while(i < numbers.size() && !found) {
				if(data2.equals(numbers.get(i))) {
					found = true;
				}
				i++;
			}
			if(!found) {
				serverTypes.put(server[0], serverTypes.get(server[0]) + 1);
				numbers.add(data2);
			}
		}
	}
	
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		try {
			LogStatistics log = new LogStatistics();
			log.procesar(args[0]);
		}
		catch(IndexOutOfBoundsException e) {
			System.err.println("No se ha introducido ningun directorio");
		}
	}

}
