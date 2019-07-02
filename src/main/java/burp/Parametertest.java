package burp;

public class Parametertest {



    public static void main(String[] args) {

        String targetparameter_test = "encData";
        String targetstring = "421421412312321encData=HDFDGASDFSDGSDAFDSFDSGSDAF23214 3213213";
        String result = " ";
        String[] arr = targetstring.split(targetparameter_test);

//        for(int i=0;i<arr.length;i++)
//            {
//
//                System.out.println(arr[i]);
//
//            }
        result = arr[1].substring(1, arr[1].length()-1);

        System.out.println(result.trim());


    }


}
