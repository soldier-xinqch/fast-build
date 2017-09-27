package com.fast.build.util;

import java.io.*;

/**
 * Created by xinch on 2017/9/27.
 */
public class FilesUtil {

    /**
     * 字节数组转为文件
     *
     * @param data
     * @return
     * @throws IOException
     */
    private static void byteArrayToFile(byte[] data, File file) throws IOException {
        InputStream sbs = new ByteArrayInputStream(data);
        byte[] buff = new byte[100];
        int rc = 0;
        FileOutputStream out = new FileOutputStream(file);
        while ((rc = sbs.read(buff, 0, 100)) > 0) {
            out.write(buff, 0, rc);
        }
        out.flush();
        out.close();
    }

    /**
     * 文件转为字节数组
     *
     * @param file
     * @return
     * @throws IOException
     */
    private static byte[] fileTobyteArray(File file) throws IOException {
        ByteArrayOutputStream swapStream = new ByteArrayOutputStream();
        FileInputStream in = new FileInputStream(file);
        byte[] buff = new byte[100];
        int rc = 0;
        while ((rc = in.read(buff, 0, 100)) > 0) {
            swapStream.write(buff, 0, rc);
        }
        swapStream.close();
        in.close();
        return swapStream.toByteArray();
    }

    /**
     * 将二进制转换成16进制
     *
     * @param buf
     * @return
     */
    private static String parseByte2HexStr(byte buf[]) {
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < buf.length; i++) {
            String hex = Integer.toHexString(buf[i] & 0xFF);
            if (hex.length() == 1) {
                hex = '0' + hex;
            }
            sb.append(hex.toUpperCase());
        }
        return sb.toString();
    }

    /**
     * 将16进制转换为二进制
     *
     * @param hexStr
     * @return
     */
    private static byte[] parseHexStr2Byte(String hexStr) {
        if (hexStr.length() < 1)
            return null;
        byte[] result = new byte[hexStr.length() / 2];
        for (int i = 0; i < hexStr.length() / 2; i++) {
            int high = Integer.parseInt(hexStr.substring(i * 2, i * 2 + 1), 16);
            int low = Integer.parseInt(hexStr.substring(i * 2 + 1, i * 2 + 2), 16);
            result[i] = (byte) (high * 16 + low);
        }
        return result;
    }
}
