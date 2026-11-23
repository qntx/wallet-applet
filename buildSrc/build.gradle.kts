plugins {
    `kotlin-dsl`
}

repositories {
    mavenCentral()
}

dependencies {
    // withGroovyBuilder wraps calls in groovy.lang.GroovyObject casts
    localGroovy()
}
