from tools.ml_inference_tool import MLInferenceTool

tool = MLInferenceTool()
features = [0]*77  # 77 zeros as test
result = tool._run(features)
print(result)