package analysis_tool;

import java.lang.reflect.Field;
import java.util.Collection;
import java.util.LinkedList;
import java.util.HashMap;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

public class Features {
	public Collection<Feature> featureList = new LinkedList<Feature>();
	HashMap<String, String> meta = new HashMap<String, String>();

	public Features() {
		;
	}

	public void add(String name, Object value, Object location, String result, Object slice, Object extra) {
		featureList.add(new Feature(String.valueOf(name), String.valueOf(value), String.valueOf(location), result, String.valueOf(slice), String.valueOf(extra)));
	}

	public String toJson() {
		HashMap<String, Object> finalResult = new HashMap<String, Object>();
		finalResult.put("meta", meta);
		finalResult.put("features", featureList);

		Gson gson = new GsonBuilder().create();
		String res = gson.toJson(finalResult);
		return res;
	}

	public String toString() {
		String toStr = "\n";
		for (Feature f : featureList) {
			toStr += "->" + String.valueOf(f.name) + ":" + String.valueOf(f.value) + "=" + String.valueOf(f.result) + "_" + String.valueOf(f.location) + "\n";
		}
		if (toStr.endsWith("\n")) {
			toStr = toStr.substring(0, toStr.length() - 1);
		}
		return toStr;
	}

	public void addMeta(String key, String value) {
		meta.put(key, value);
	}
}