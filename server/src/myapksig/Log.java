package myapksig;

public class Log {
    public static void error(String tag, String message){
        System.err.println(tag + ": "+ message);
    }

    public static void info(String message){
        System.out.println(message);
    }
}
