import streamlit as st 
import urllib
import matplotlib.pyplot as plt
#Numpy deals with large arrays and linear algebra
import pandas as pd
# Library for data manipulation and analysis
import numpy as np
np.random.seed(0)
# Metrics for Evaluation of model Accuracy, Precision, Recall and F1-score
from sklearn.metrics import precision_score,recall_score,f1_score,accuracy_score
import matplotlib.pyplot as plt
# For splitting of data into train and test set
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import ConfusionMatrixDisplay
from sklearn.metrics import confusion_matrix
#Importing the Decision Tree from scikit-learn library
from sklearn.tree import DecisionTreeClassifier 
from sklearn.linear_model import LogisticRegression
from sklearn.linear_model import LinearRegression
from sklearn.svm import SVC
from sklearn.naive_bayes import GaussianNB
from sklearn.naive_bayes import MultinomialNB
from sklearn.neighbors import KNeighborsClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.ensemble import GradientBoostingClassifier

from mlxtend.evaluate import bias_variance_decomp




import altair as alt

@st.cache_data(persist= True)
def load():
     data = pd.read_csv("drebin-215-dataset-5560malware-9476-benign.csv")
     return data

def plot_metrics(metrics_list):
    if "Confusion Matrix" in metrics_list:
        st.subheader("Confusion Matrix")
        cm = confusion_matrix(y_test,y_pred)
        ConfusionMatrixDisplay(confusion_matrix=cm,display_labels=class_names)        
        st.pyplot()
    if "ROC Curve" in metrics_list:
        st.subheader("ROC Curve")
        plot_roc_curve(model, x_test, y_test)
        st.pyplot()
   
class_names = ["benign", "malware"]

@st.cache_data(persist=True)
def split(data):
    x_train,x_test,y_train,y_test = train_test_split(data[data.columns[:len(data.columns)-1]].to_numpy(),
                                                 data[data.columns[-1]].to_numpy(),
                                                  test_size = 0.25,
                                                  shuffle=True)    
    return x_train, x_test, y_train, y_test

# write a function for toggle functionality
def toggle():
    if st.session_state.button:
        st.session_state.button = False
    else:
        st.session_state.button = True

def main():  

    try:
        st.set_page_config(layout="wide") 

        st.markdown("## AI and ML Technology in Cyber Security Assignment")
        st.markdown("### Submission by: Aparna Khare (2021mt13119@wilp.bits-pilani.ac.in)")
        st.sidebar.title("Android Malware Dataset Analysis")    
        st.markdown('----')


        if "button" not in st.session_state:
            st.session_state.button = False

        

        # create the button
        st.sidebar.button("Toggle View Data Analysis", on_click=toggle)


        with st.expander(label="Dataset Analysis", expanded=st.session_state.button):

            st.sidebar.header("About the Dataset")
            st.sidebar.write("The dataset consists of two csv files - dataset-features-categories.csv and drebin-215-dataset-5560malware-9476-benign.csv. The first csv (dataset-features-categories.csv) is a supporting file that contains the list of the feature vectors/ attributes that were acquired through the static code analysis of the android apps. These form the basis of the main dataset, the second csv file (drebin-215-dataset-5560malware-9476-benign.csv) that contains feature vectors of 215 attributes extracted from 15,036 applications (5,560 malware apps from 179 different malware families from Drebin project and 9,476 benign apps).")
            
            st.markdown("### :blue[Dataset Analysis]")       
            (col1, col2) = st.columns(2)
            categories = pd.read_csv("dataset-features-categories.csv",header=None,names=['Entry', 'MainCategoryType'])
            categories = categories[:-1]
            with col1:
                 
                 st.markdown("#### :green[**_dataset-features-categories.csv_**]")
                 st.write(categories)

            with col2:

                 st.markdown("#### Division of MainCategoryTypes")
                 (innercol1, innercol2) = st.columns(2)
                 entry_num =  categories.groupby('MainCategoryType')['Entry'].count()

                 with innercol1:            
                    st.dataframe(entry_num, use_container_width=True)
                 #entry_num.plot(kind='bar', title='Division of MainCategoryTypes', ylabel='Count', xlabel='MainCategoryType', figsize=(6, 5))
                 with innercol2:
                    st.bar_chart(entry_num)
                 
                
                 st.write(":blue[The categories for the dataset was analysed. The Main Categories were identified and group by to find the count of entries for the Main Category Types.]")
                    

            
            data = load()
            st.markdown("#### :green[**_Malware Dataset: drebin-215-dataset-5560malware-9476-benign.csv_**]")
            st.write(data)
            st.write("Total missing values : ",sum(list(data.isna().sum())))

            classes,count = np.unique(data['class'],return_counts=True)
            #Perform Label Encoding
            lbl_enc = LabelEncoder()
            print(lbl_enc.fit_transform(classes),classes)
            data = data.replace(classes,lbl_enc.fit_transform(classes))
            data=data.replace('[?,S]',np.NaN,regex=True)
            print("Total missing values : ",sum(list(data.isna().sum())))
            data.dropna(inplace=True)
            for c in data.columns:
                data[c] = pd.to_numeric(data[c])
            
            c1, c3, c5= st.columns([1, 4, 1])
            with c3:
                bar_colors = ['tab:blue', '#fc5a50']
                hbars=plt.barh(classes,count,color=bar_colors)
                plt.title("Class balance")
                plt.xlabel("Classes")
                plt.ylabel("Count")
                plt.title('Analyzing Class Imbalance between the 2 Classes in Dataset')
                plt.bar_label(hbars, fmt='%.0f', label_type='center')
                st.pyplot(plt.gcf())


        #x_train, x_test, y_train, y_test = split(data)

        st.sidebar.subheader("Choose classifier")
        classifier = st.sidebar.selectbox("Classifier", ("Decision Tree", "Random Forest"))  
        
        if classifier == "Decision Tree":
            #st.sidebar.subheader("Options")
            #metrics = st.sidebar.multiselect("What metrics to plot?", ("Confusion Matrix", "ROC Curve"))
            #metrics = st.sidebar.multiselect("What metrics to plot?", ("Confusion Matrix","Metrics"))
            
            if st.sidebar.button("Classify", key="classify"):
                st.subheader("Decision Tree Results")

                x_train,x_test,y_train,y_test = train_test_split(data[data.columns[:len(data.columns)-1]].to_numpy(),
                                             data[data.columns[-1]].to_numpy(),
                                              test_size = 0.25,
                                              shuffle=True)  

                model = DecisionTreeClassifier()
                model.fit(x_train, y_train)
                y_pred = model.predict(x_test)
                               
                st.write("Precision: ", precision_score(y_test, y_pred, labels=class_names).round(5)*100)
                st.write("Recall: ", recall_score(y_test, y_pred, labels=class_names).round(5)*100)
                st.write("F1 Score: ", f1_score(y_test, y_pred, labels=class_names).round(5)*100)

               
                # if "Confusion Matrix" in metrics:
                c1, c3, c5= st.columns([1, 4, 1])
                with c3:
                    st.subheader("Confusion Matrix")
                    cm = confusion_matrix(y_test,y_pred)
                    disp = ConfusionMatrixDisplay(confusion_matrix=cm,display_labels=class_names)   
                    fig, ax = plt.subplots(figsize=(7,7))
                    plt.title("Confusion Matrix for Decision Tree")
                    disp = disp.plot(ax=ax)
                    #plt.show()     
                    st.pyplot(plt.gcf())


                # if "ROC Curve" in metrics:
                #     c1, c3, c5= st.columns([1, 4, 1])
                #     with c3:
                #         st.subheader("ROC Curve for Decision Tree")
                #         #define metrics
                #         y_pred_proba = model.predict_proba(x_test)[::,1]
                #         fpr, tpr, _ = metrics.roc_curve(y_test,  y_pred_proba)

                #         #create ROC curve
                #         plt.plot(fpr,tpr)
                #         plt.ylabel('True Positive Rate')
                #         plt.xlabel('False Positive Rate')
                #         st.pyplot(plt.gcf())
                
                # #pip install mlxtend
                # mse, bias, var = bias_variance_decomp(model, x_train, y_train, x_test, y_test, loss='mse', num_rounds=200, random_seed=123)
                # # summarize results
                # st.write('MSE from bias_variance lib [avg expected loss]: %.3f' % mse)
                # st.write('Avg Bias: %.3f' % bias)
                # st.write('Avg Variance: %.3f' % var)
                # st.write('Mean Square error by Sckit-learn lib: %.3f' % metrics.mean_squared_error(test_y,y_pred))
                       



        if classifier == "Random Forest":
            st.sidebar.subheader("Hyperparameters")
            n_estimators= st.sidebar.number_input("The number of trees in the forest", 100, 5000, step=10, key="n_estimators")
            #max_depth = st.sidebar.number_input("The maximum depth of tree", 1, 20, step =1, key="max_depth")
           
            #metrics = st.sidebar.multiselect("What metrics to plot?", ("Confusion Matrix", "ROC Curve"))
            
            
            
            if st.sidebar.button("Classify", key="classify"):
                st.subheader("Random Forest Results")
                x_train,x_test,y_train,y_test = train_test_split(data[data.columns[:len(data.columns)-1]].to_numpy(),
                                             data[data.columns[-1]].to_numpy(),
                                              test_size = 0.25,
                                              shuffle=True)  
                model = RandomForestClassifier(n_estimators=n_estimators)
                model.fit(x_train, y_train)
                accuracy = model.score(x_test, y_test)
                y_pred = model.predict(x_test)                   
                st.write("Precision: ", precision_score(y_test, y_pred, labels=class_names).round(5)*100)
                st.write("Recall: ", recall_score(y_test, y_pred, labels=class_names).round(5)*100)
                st.write("F1 Score: ", f1_score(y_test, y_pred, labels=class_names).round(5)*100)

               
                #if "Confusion Matrix" in metrics:
                c1, c3, c5= st.columns([1, 4, 1])
                with c3:
                    st.subheader("Confusion Matrix")
                    cm = confusion_matrix(y_test,y_pred)
                    disp = ConfusionMatrixDisplay(confusion_matrix=cm,display_labels=class_names)   
                    fig, ax = plt.subplots(figsize=(7,7))
                    plt.title("Confusion Matrix for Random Forest")
                    disp = disp.plot(ax=ax)
                    #plt.show()     
                    st.pyplot(plt.gcf())


                # if "ROC Curve" in metrics:
                #     c1, c3, c5= st.columns([1, 4, 1])
                #     with c3:
                #         st.subheader("ROC Curve for Random Forest")
                #         #define metrics
                #         y_pred_proba = model.predict_proba(x_test)[::,1]
                #         fpr, tpr, _ = metrics.roc_curve(y_test,  y_pred_proba)

                #         #create ROC curve
                #         plt.plot(fpr,tpr)
                #         plt.ylabel('True Positive Rate')
                #         plt.xlabel('False Positive Rate')
                #         st.pyplot(plt.gcf())
        
    except Exception as e:
        print(e)       
             

if __name__=='__main__':
    main()
