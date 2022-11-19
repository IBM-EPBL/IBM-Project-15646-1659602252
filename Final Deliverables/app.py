from flask import Flask, request, render_template
import numpy as np
import FeatureExtractor
import pickle

app = Flask(__name__)

@app.route("/")
def welcome():
    return render_template("index.html");

@app.route("/about")
def about():
    return render_template("about.html");

@app.route("/product")
def product():
    return render_template("product.html")

@app.route("/predict", methods=['POST'])
def predict():

    # getting the URL from the website
    url = request.form["url"]
    # url = "https://www.linkedin.com/"

    # loading the saved model
    model = getModel()

    # getting the features from the url
    features = FeatureExtractor.getFeatures(url)

    result = model.predict(features)
    # probability = model.predict_proba(features)
    result = result.tolist()
    print(type(result))
    print(result)
    # print(probability)

    # result = [1]
    message = ""
    if(result[0] == 1):
        message = "Legitimate site"
    else:
        message = "Suspecious site"
    return render_template("product.html", message = message, url = url)

def getModel():
    file = open("./model.pkl","rb")
    model = pickle.load(file)
    file.close()
    return model

def getFeaturesFromURL(url: str) -> np.ndarray:
    features = FeatureExtractor.getFeatures(url)
    features = np.array(features).reshape(1, 27)
    return features

if __name__ == "__main__":
    app.run(debug = True)