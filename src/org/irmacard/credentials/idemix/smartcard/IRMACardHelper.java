package org.irmacard.credentials.idemix.smartcard;

import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.file.Files;
import java.nio.file.Path;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

public class IRMACardHelper {
	public static String serializeState(IRMACard card) {
		Gson gson = new GsonBuilder().setPrettyPrinting().create();
		return gson.toJson(card);
	}

	public static void storeState(IRMACard card, Path cardStoragePath) {
		Writer writer = null;
		try {
		    writer = new BufferedWriter(new OutputStreamWriter(
		          new FileOutputStream(cardStoragePath.toString()), "utf-8"));
		    writer.write(serializeState(card));
		} catch (IOException exception) {
			exception.printStackTrace();
		} finally {
		   try {writer.close();} catch (Exception ex) {}
		}
	}

	public static IRMACard loadState(String state) {
		Gson gson = new Gson();
		return gson.fromJson(state, IRMACard.class);
	}

	public static IRMACard loadState(Path cardStoragePath) {
		try {
			byte[] data = Files.readAllBytes(cardStoragePath);
			return loadState(new String(data));
		} catch (IOException e) {
			e.printStackTrace();
			return new IRMACard();
		}
	}
}
