package at.innoc.roboat.radar;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.net.UnknownHostException;

import at.innoc.roboat.radar.control.LiveControl;
import at.innoc.roboat.radar.helpers.IpHelper;

public class RadarUdpSource implements RadarSource, Runnable {
        private DatagramSocket socket;
        private DatagramPacket datagram;
        private static Thread keepAliveThread = null;
        private static boolean keepAliveStop;
        private static LiveControl control;

        public RadarUdpSource(LiveControl controlchannel) throws UnknownHostException, IOException {
                this(controlchannel, 6678);
        }

        public RadarUdpSource(LiveControl controlchannel, int port) throws UnknownHostException, IOException {
                control = controlchannel;
                try {
                        Object[] result = IpHelper.getMachineIp();
                        if (result[0] == null) {
                                throw new UnknownHostException((String) result[1]);
                        }
                        InetAddress interfaceAddress = InetAddress.getByName((String) result[0]);
                        socket = new DatagramSocket(new InetSocketAddress(interfaceAddress, port));
                } catch (UnknownHostException e) {
                        e.printStackTrace();
                } catch (IOException e) {
                        e.printStackTrace();
                }

                datagram = new DatagramPacket(new byte[80000], 80000);
                keepAliveStop = false;
                if (keepAliveThread == null) {
                        keepAliveThread = new Thread(this);
                        keepAliveThread.setDaemon(true);
                        keepAliveThread.start();
                }
        }

        @Override
        public RadarDataFrame getNextDataFrame() {
                byte[] ret;
                try {
                        socket.receive(datagram);
                        long time = System.currentTimeMillis();
                        ret = java.util.Arrays.copyOfRange(datagram.getData(), datagram.getOffset(), datagram.getLength());
                        return new RadarDataFrame(ret, time);
                } catch (SocketException se) {
                        System.out.println(se + "");
                        return new RadarDataFrame();
                } catch (IOException e) {
                        e.printStackTrace();
                        return new RadarDataFrame();
                }
        }

        @Override
        public void close() {
                keepAliveStop = true;
                socket.close();
        }

        @Override
        public void run() {
                while (!keepAliveStop) {
                        try {
                                Thread.sleep(1000);
                                control.sendKeepAlive();
                        } catch (Exception e) {
                        }
                }
        }
}
