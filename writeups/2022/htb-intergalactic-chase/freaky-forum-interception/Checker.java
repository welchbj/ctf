import java.util.stream.IntStream;

public class Checker {
  public static boolean hello_java(String paramString) {
    int[] arrayOfInt = { 219, 227, 209, 154, 104, 97, 158, 163 };
    return (
		IntStream.range(0, paramString.length() - 1).mapToObj(
			paramInt -> new Object[] {
                // idx, paramString[idx], paramString[idx+1]
				Integer.valueOf(paramInt), Integer.valueOf(paramString.charAt(paramInt)), Integer.valueOf(paramString.charAt(paramInt + 1))
			}
		).filter(
			paramArrayOfObject -> (
                ((Integer)paramArrayOfObject[1]).intValue() + ((Integer)paramArrayOfObject[2]).intValue() == paramArrayOfint[((Integer)paramArrayOfObject[0]).intValue()])
        ).count() == (paramString.length() - 1));
  }
}

