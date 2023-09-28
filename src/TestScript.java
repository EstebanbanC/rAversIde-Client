//Premier script : 
//Récupère le contenu d'une page web et l'affiche dans la console.
//@author Baptiste
//@category Examples._MASTER_PROJECT_

import ghidra.app.script.GhidraScript;
import ghidra.framework.generic.auth.Password;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

public class TestScript extends GhidraScript {

    @Override
    public void run() throws Exception {

        try {
            println("Début du Script !");
            // URL de la page web que vous souhaitez récupérer
            String urlStr = "http://127.0.0.1:7878";
            
            // Créez un objet URL à partir de l'URL spécifiée
            URL url = new URL(urlStr);
            
            // Ouvrez une connexion HTTP vers l'URL
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            
            // Définissez la méthode de requête (par exemple, GET)
            connection.setRequestMethod("GET");
            
            // Obtenez le code de réponse HTTP
            int responseCode = connection.getResponseCode();
            
            if (responseCode == HttpURLConnection.HTTP_OK) {
                // Créez un BufferedReader pour lire la réponse de la page web
                BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
                String line;
                
                // Lisez et affichez chaque ligne de la réponse
                while ((line = reader.readLine()) != null) {
                    println(line);
                }
                
                // Fermez le BufferedReader
                reader.close();
            } else {
                println("La requête a échoué avec le code : " + responseCode);
            }
            
            // Fermez la connexion HTTP
            connection.disconnect();
        }
        catch (IllegalArgumentException iae) {
            Msg.warn(this, "Error during headless processing: " + iae.toString());
        }

    }
}
