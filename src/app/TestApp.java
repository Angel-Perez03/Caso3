package app;

import server.MainServer;
import client.Client;

public class TestApp {
    public static void main(String[] args) throws Exception {
        Thread srv = new Thread(() -> {
            try { MainServer.main(new String[]{}); } catch(Exception e){ e.printStackTrace(); }
        });
        srv.setDaemon(true);
        srv.start();
        Thread.sleep(500);
        Client.main(new String[]{});
    }
}
