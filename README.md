﻿# Web_Application_Firewall
 ![image](https://github.com/Pratham-verma/Web_Application_Firewall/assets/89769653/b094c5d1-e6bb-43ed-b0ca-9e140aeb7914)

This project is a Web Application Firewall (WAF) designed to protect web applications from malicious requests. By leveraging **Machine Learning** , specifically Logistic Regression, the WAF can distinguish between good (legitimate) and bad (malicious) requests. The solution involves a proxy server that intercepts incoming requests, evaluates them using a trained ML model, and determines whether to allow or block the request based on the prediction.

Project Video : [youtube](https://youtu.be/qSO4cmMWiCg)

## Table of Contents

| Section                                           | Description                                                             |
|---------------------------------------------------|-------------------------------------------------------------------------|
| [Overview](#overview)                             | Introduction to the Web Application Firewall (WAF) project.              |
| [Features](#features)                             | Key features of the WAF including proxy server, ML model, and logging.   |
| [Architecture](#architecture)                     | Overview of the components and workflow of the WAF.                     |
| [Tech Stack](#tech-stack)                         | Technologies and tools used in the project.                             |
| [Installation](#installation)                     | Step-by-step guide to install the WAF.                                  |
| [Usage](#usage)                                   | Instructions on how to run and use the WAF.                             |
| [Dataset](#dataset)                               | Details on the dataset used for training the ML model.                  |
| [Machine Learning Model](#machine-learning-model) | Information on the ML model and training process.                       |
| [Contributing](#contributing)                     | Guidelines for contributing to the project.                             |                             |

## Overview

Web Application Firewalls (WAFs) are critical components for protecting web applications from attacks such as SQL injection, Cross-Site Scripting (XSS), and other OWASP Top 10 vulnerabilities. This WAF uses a Logistic Regression model to classify incoming HTTP requests as either good or bad, enhancing the security of the web application it protects.

## Features

- **Proxy Server**: Intercepts incoming HTTP requests and forwards them to the web server if deemed safe.
- **Machine Learning Model**: Logistic Regression model trained to detect malicious requests.
- **Real-Time Request Analysis**: Analyzes and classifies requests in real-time.

## Architecture

The architecture of the WAF is composed of the following components:

1. **Proxy Server**: Acts as an intermediary between the client and the web server.
2. **Request Logger**: Logs incoming requests for analysis and model training.
3. **Feature Extractor**: Extracts relevant features from HTTP requests for ML model input.
4. **Logistic Regression Model**: Trained model to classify requests as good or bad.
5. **Decision Engine**: Uses the model's prediction to allow or block the request.

## Tech Stack

- **Programming Language**: Python
- **Machine Learning Library**: Scikit-learn
- **Data Handling**: Pandas
- **HTTP Handling**: Requests
- **Logging**: Python's logging module
- **Network Security**: Integration of security best practices and protocols
- **Web Security**: Implementing security measures to protect against these vulnerabilities. 

## Installation

 **Clone the Repository**:
   ```sh
   git clone https://github.com/Pratham-verma/Web_Application_Firewall.git
   ```

## Usage

1. **Run the Proxy Server**:
   ```sh
   python proxy_server.py
   ```

2. **Monitor Logs**:
   Check the logs generated by the proxy server to see the classification of requests.

## Dataset

The dataset used for training the Logistic Regression model consists of labeled HTTP requests. Each request is classified as either good (legitimate) or bad (malicious). The dataset includes various features extracted from the HTTP headers, body, and other metadata.

To prepare the dataset:

1. Collect a large number of HTTP requests from various sources.
2. Label the requests as good or bad.
3. Extract features from each request.
4. Split the dataset into training and testing sets.

## Machine Learning Model

The Logistic Regression model is trained using the prepared dataset. The model learns to identify patterns and features that distinguish good requests from bad ones.

### Training the Model

1. **Prepare the Dataset**:
   Ensure your dataset is in a suitable format (e.g., CSV) with labeled features.

2. **Train the Model**:
   ```python
   from sklearn.model_selection import train_test_split
   from sklearn.linear_model import LogisticRegression
   import pandas as pd

   # Load dataset
   data = pd.read_csv('dataset.csv')
   X = data.drop('label', axis=1)
   y = data['label']

   # Split the dataset
   X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

   # Train the model
   model = LogisticRegression()
   model.fit(X_train, y_train)
   ```

3. **Evaluate the Model**:
   ```python
   from sklearn.metrics import accuracy_score, classification_report

   # Predict and evaluate
   y_pred = model.predict(X_test)
   print(accuracy_score(y_test, y_pred))
   print(classification_report(y_test, y_pred))
   ```

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request with your improvements.

## thank you


