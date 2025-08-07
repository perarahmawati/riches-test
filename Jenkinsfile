pipeline {
  agent { label 'fortify-sensor'}
  
  stages {
    stage('Git Clone') {
      agent { label 'fortify-sensor'}
      steps {
        git branch: 'master', url: 'https://github.com/fortify/riches.git' 
      } 
    }
    stage('Fortify Update') {
      agent { label 'fortify-sensor'}
      steps {
        fortifyUpdate  updateServerURL: 'https://update.fortify.com'
      }
    }
    stage('Fortify Clean') {
      agent { label 'fortify-sensor'}
      steps {
        fortifyClean buildID: 'riches'
       }
    }
    stage('Fortify Translate') {
      agent { label 'fortify-sensor'}
      steps {
        fortifyTranslate buildID: 'riches', 
          projectScanType: fortifyJava(javaSrcFiles: 
'WEB-INF/src/java/com/fortify/samples/riches/**/*.java', javaVersion: '11')
      }
    }
    stage('Fortify Scan') {
      agent { label 'fortify-sensor'}
      steps {
        fortifyScan buildID: 'riches', 
          resultsFile: 'riches.fpr'
       }
    }
    stage('Fortify Upload') {
      agent { label 'fortify-sensor'}
      steps {
        fortifyUpload appName: 'riches', appVersion: '2.0', 
          resultsFile: 'riches.fpr'
       }
    }
  }
}